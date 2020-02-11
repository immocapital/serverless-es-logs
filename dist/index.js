"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
const fs_extra_1 = __importDefault(require("fs-extra"));
const lodash_1 = __importDefault(require("lodash"));
const path_1 = __importDefault(require("path"));
const axios_1 = __importDefault(require("axios"));
const utils_1 = require("./utils");
// tslint:disable:no-var-requires
const iamLambdaTemplate = require('../templates/iam/lambda-role.json');
const withXrayTracingPermissions = require('../templates/iam/withXrayTracingPermissions.js');
const aws = require('aws-sdk');
const aws_v4_signer = require('aws4');
// tslint:enable:no-var-requires
class ServerlessEsLogsPlugin {
    constructor(serverless, options) {
        this.logProcesserDir = '_es-logs';
        this.logProcesserName = 'esLogsProcesser';
        this.defaultLambdaFilterPattern = '[timestamp=*Z, request_id="*-*", event]';
        this.defaultApiGWFilterPattern = '[event]';
        this.defaultUseApiGatewayPipeline = false;
        this.serverless = serverless;
        this.provider = serverless.getProvider('aws');
        this.options = options;
        const normalizedName = this.provider.naming.getNormalizedFunctionName(this.logProcesserName);
        this.logProcesserLogicalId = `${normalizedName}LambdaFunction`;
        // tslint:disable:object-literal-sort-keys
        this.hooks = {
            'after:package:initialize': this.afterPackageInitialize.bind(this),
            'after:package:createDeploymentArtifacts': this.afterPackageCreateDeploymentArtifacts.bind(this),
            'aws:package:finalize:mergeCustomProviderResources': this.mergeCustomProviderResources.bind(this),
        };
        // tslint:enable:object-literal-sort-keys
    }
    custom() {
        // Instance of custom will be replaced based on which lifecycle hooks have been evaluated
        // always fetch a fresh instance
        return this.serverless.service.custom || {};
    }
    afterPackageCreateDeploymentArtifacts() {
        this.serverless.cli.log('ServerlessEsLogsPlugin.afterPackageCreateDeploymentArtifacts()');
        this.cleanupFiles();
    }
    afterPackageInitialize() {
        this.serverless.cli.log('ServerlessEsLogsPlugin.afterPackageInitialize()');
        this.formatCommandLineOpts();
        this.validatePluginOptions();
        // Add log processing lambda
        // TODO: Find the right lifecycle method for this
        this.addLogProcesser();
    }
    mergeCustomProviderResources() {
        return __awaiter(this, void 0, void 0, function* () {
            this.serverless.cli.log('ServerlessEsLogsPlugin.mergeCustomProviderResources()');
            const { includeApiGWLogs, retentionInDays, useDefaultRole, xrayTracingPermissions } = this.custom().esLogs;
            const template = this.serverless.service.provider.compiledCloudFormationTemplate;
            // Add cloudwatch subscriptions to firehose for functions' log groups
            this.addLambdaCloudwatchSubscriptions();
            // Configure Cloudwatch log retention
            if (retentionInDays !== undefined) {
                this.configureLogRetention(retentionInDays);
            }
            // Add xray permissions if option is enabled
            if (xrayTracingPermissions === true) {
                const statement = iamLambdaTemplate.ServerlessEsLogsLambdaIAMRole.Properties.Policies[0].PolicyDocument.Statement;
                statement.push(withXrayTracingPermissions);
            }
            // Add IAM role for cloudwatch -> elasticsearch lambda
            if (this.serverless.service.provider.role && !useDefaultRole) {
                lodash_1.default.merge(template.Resources, iamLambdaTemplate);
                this.patchLogProcesserRole();
            }
            else if (!this.serverless.service.provider.role) {
                // Merge log processor role policies into default role
                const updatedPolicies = template.Resources.IamRoleLambdaExecution.Properties.Policies.concat(iamLambdaTemplate.ServerlessEsLogsLambdaIAMRole.Properties.Policies);
                template.Resources.IamRoleLambdaExecution.Properties.Policies = updatedPolicies;
            }
            // Add cloudwatch subscription for API Gateway logs
            if (includeApiGWLogs === true) {
                yield this.addApiGwCloudwatchSubscription();
            }
        });
    }
    formatCommandLineOpts() {
        this.options.stage = this.options.stage
            || this.serverless.service.provider.stage
            || (this.serverless.service.defaults && this.serverless.service.defaults.stage)
            || 'dev';
        this.options.region = this.options.region
            || this.serverless.service.provider.region
            || (this.serverless.service.defaults && this.serverless.service.defaults.region)
            || 'us-east-1';
    }
    validatePluginOptions() {
        const { esLogs } = this.custom();
        if (!esLogs) {
            throw new this.serverless.classes.Error(`ERROR: No configuration provided for serverless-es-logs!`);
        }
        const { endpoint, index, tags } = esLogs;
        if (!endpoint) {
            throw new this.serverless.classes.Error(`ERROR: Must define an endpoint for serverless-es-logs!`);
        }
        if (!index) {
            throw new this.serverless.classes.Error(`ERROR: Must define an index for serverless-es-logs!`);
        }
        if (tags && !lodash_1.default.isPlainObject(tags)) {
            throw new this.serverless.classes.Error(`ERROR: Tags must be an object! You provided '${tags}'.`);
        }
    }
    createApiGatewayElasticsearchPipeline() {
        return __awaiter(this, void 0, void 0, function* () {
            const { esLogs } = this.custom();
            const endpoint = esLogs.endpoint;
            const useApiGatewayPipeline = esLogs.useApiGatewayPipeline || this.defaultUseApiGatewayPipeline;
            const pipeline = 'ApiGatewayPipeline';
            if (!useApiGatewayPipeline) {
                return;
            }
            const sts = new aws.STS();
            const session_token = yield sts.getSessionToken().promise();
            const credentials = {
                'secretAccessKey': session_token.Credentials.SecretAccessKey,
                'accessKeyId': session_token.Credentials.AccessKeyId,
                'sessionToken': session_token.Credentials.SessionToken,
            };
            const requestOptions = {
                url: `https://${endpoint}/_ingest/pipeline/${pipeline}`,
                method: 'GET',
            };
            const signed = aws_v4_signer.sign({
                hostname: endpoint,
                path: `/_ingest/pipeline/${pipeline}`
            }, credentials);
            requestOptions['headers'] = signed.headers;
            try {
                const pipelines = yield axios_1.default(requestOptions);
                if (pipelines.status === 200) {
                    this.serverless.cli.log(`Pipeline ${pipeline} already exists! Continuing...`);
                    return;
                }
            }
            catch (error) {
                if (error.response.status === 404) {
                    this.serverless.cli.log(`Creating pipeline ${pipeline}...`);
                }
                else {
                    throw new this.serverless.classes.Error(`ERROR: Failed to create pipeline '${pipeline}': ${error.message}.`);
                }
            }
            const createPipelineRequestOptions = {
                url: `https://${endpoint}/_ingest/pipeline/${pipeline}`,
                method: 'PUT',
                data: {
                    "description": "Pipeline for structuring API Gateway logs.",
                    "processors": [
                        {
                            "grok": {
                                "field": "@message",
                                "patterns": [
                                    "^requestId: %{UUID:requestId}, ip: %{IP:ip}, caller: %{GREEDYDATA:caller}, user: %{USER:user}, requestTime: %{HTTPDATE:requestTime}, httpMethod: %{WORD:httpMethod}, resourcePath: %{URIPATHPARAM:resourcePath}, status: %{NUMBER:status}, protocol: %{GREEDYDATA:protocol}, responseLength: %{NUMBER:responseLength}$",
                                    "${GREEDYDATA}"
                                ]
                            }
                        }
                    ]
                },
                headers: {
                    'Content-Type': 'application/json'
                }
            };
            const signedPip = aws_v4_signer.sign({
                hostname: endpoint,
                path: `/_ingest/pipeline/${pipeline}`,
                method: 'PUT',
                body: JSON.stringify(createPipelineRequestOptions.data),
                headers: createPipelineRequestOptions.headers
            }, credentials);
            createPipelineRequestOptions['headers'] = signedPip.headers;
            try {
                yield axios_1.default(createPipelineRequestOptions);
            }
            catch (error) {
                throw error;
            }
            this.serverless.cli.log(`Pipeline ${pipeline} successfully created!`);
        });
    }
    addApiGwCloudwatchSubscription() {
        return __awaiter(this, void 0, void 0, function* () {
            const { esLogs } = this.custom();
            const filterPattern = esLogs.apiGWFilterPattern || this.defaultApiGWFilterPattern;
            const apiGwLogGroupLogicalId = 'ApiGatewayLogGroup';
            const template = this.serverless.service.provider.compiledCloudFormationTemplate;
            // Check if API Gateway log group exists
            /* istanbul ignore else */
            yield this.createApiGatewayElasticsearchPipeline();
            if (template && template.Resources[apiGwLogGroupLogicalId]) {
                const { LogGroupName } = template.Resources[apiGwLogGroupLogicalId].Properties;
                const subscriptionLogicalId = `${apiGwLogGroupLogicalId}SubscriptionFilter`;
                const permissionLogicalId = `${apiGwLogGroupLogicalId}CWPermission`;
                const processorFunctionName = template.Resources[this.logProcesserLogicalId].Properties.FunctionName;
                // Create permission for subscription filter
                const permission = new utils_1.LambdaPermissionBuilder()
                    .withFunctionName(processorFunctionName)
                    .withPrincipal({
                    'Fn::Sub': 'logs.${AWS::Region}.amazonaws.com',
                })
                    .withSourceArn({
                    'Fn::Join': [
                        '',
                        [
                            'arn:aws:logs:',
                            {
                                Ref: 'AWS::Region',
                            },
                            ':',
                            {
                                Ref: 'AWS::AccountId',
                            },
                            ':log-group:',
                            LogGroupName,
                            '*',
                        ],
                    ],
                })
                    .withDependsOn([this.logProcesserLogicalId, apiGwLogGroupLogicalId])
                    .build();
                // Create subscription filter
                const subscriptionFilter = new utils_1.SubscriptionFilterBuilder()
                    .withDestinationArn({
                    'Fn::GetAtt': [
                        this.logProcesserLogicalId,
                        'Arn',
                    ],
                })
                    .withFilterPattern(filterPattern)
                    .withLogGroupName(LogGroupName)
                    .withDependsOn([this.logProcesserLogicalId, permissionLogicalId])
                    .build();
                // Create subscription template
                const subscriptionTemplate = new utils_1.TemplateBuilder()
                    .withResource(permissionLogicalId, permission)
                    .withResource(subscriptionLogicalId, subscriptionFilter)
                    .build();
                lodash_1.default.merge(template, subscriptionTemplate);
            }
        });
    }
    addLambdaCloudwatchSubscriptions() {
        const { esLogs } = this.custom();
        const filterPattern = esLogs.filterPattern || this.defaultLambdaFilterPattern;
        const template = this.serverless.service.provider.compiledCloudFormationTemplate;
        const functions = this.serverless.service.getAllFunctions();
        // Add cloudwatch subscription for each function except log processer
        functions.forEach((name) => {
            /* istanbul ignore if */
            if (name === this.logProcesserName) {
                return;
            }
            const normalizedFunctionName = this.provider.naming.getNormalizedFunctionName(name);
            const subscriptionLogicalId = `${normalizedFunctionName}SubscriptionFilter`;
            // const permissionLogicalId = `${normalizedFunctionName}CWPermission`;
            const logGroupLogicalId = `${normalizedFunctionName}LogGroup`;
            const logGroupName = template.Resources[logGroupLogicalId].Properties.LogGroupName;
            // Create permission for subscription filter
            // const permission = new LambdaPermissionBuilder()
            //   .withFunctionName({
            //     'Fn::GetAtt': [
            //       this.logProcesserLogicalId,
            //       'Arn',
            //     ],
            //   })
            //   .withPrincipal({
            //     'Fn::Sub': 'logs.${AWS::Region}.amazonaws.com',
            //   })
            //   .withSourceArn({
            //     'Fn::GetAtt': [
            //       logGroupLogicalId,
            //       'Arn',
            //     ],
            //   })
            //   .withDependsOn([ this.logProcesserLogicalId, logGroupLogicalId ])
            //   .build();
            // Create subscription filter
            const subscriptionFilter = new utils_1.SubscriptionFilterBuilder()
                .withDestinationArn({
                'Fn::GetAtt': [
                    this.logProcesserLogicalId,
                    'Arn',
                ],
            })
                .withFilterPattern(filterPattern)
                .withLogGroupName(logGroupName)
                .withDependsOn([this.logProcesserLogicalId, logGroupLogicalId])
                .build();
            // Create subscription template
            const subscriptionTemplate = new utils_1.TemplateBuilder()
                // .withResource(permissionLogicalId, permission)
                .withResource(subscriptionLogicalId, subscriptionFilter)
                .build();
            lodash_1.default.merge(template, subscriptionTemplate);
        });
    }
    configureLogRetention(retentionInDays) {
        const template = this.serverless.service.provider.compiledCloudFormationTemplate;
        Object.keys(template.Resources).forEach((key) => {
            if (template.Resources[key].Type === 'AWS::Logs::LogGroup') {
                template.Resources[key].Properties.RetentionInDays = retentionInDays;
            }
        });
    }
    addLogProcesser() {
        const { index, endpoint, tags, useApiGatewayPipeline } = this.custom().esLogs;
        const tagsStringified = tags ? JSON.stringify(tags) : /* istanbul ignore next */ '';
        const dirPath = path_1.default.join(this.serverless.config.servicePath, this.logProcesserDir);
        const filePath = path_1.default.join(dirPath, 'index.js');
        const handler = `${this.logProcesserDir}/index.handler`;
        const name = `${this.serverless.service.service}-${this.options.stage}-es-logs-plugin`;
        const apiGatewayPipelineName = useApiGatewayPipeline ? 'ApiGatewayPipeline' : '';
        fs_extra_1.default.ensureDirSync(dirPath);
        fs_extra_1.default.copySync(path_1.default.resolve(__dirname, '../templates/code/logsToEs.js'), filePath);
        this.serverless.service.functions[this.logProcesserName] = {
            description: 'Serverless ES Logs Plugin',
            environment: {
                ES_ENDPOINT: endpoint,
                ES_APIGATEWAY_PIPELINE: apiGatewayPipelineName,
                ES_INDEX_PREFIX: index,
                ES_TAGS: tagsStringified,
            },
            events: [],
            handler,
            memorySize: 512,
            name,
            package: {
                exclude: ['**'],
                include: [`${this.logProcesserDir}/**`],
                individually: true,
            },
            runtime: 'nodejs10.x',
            timeout: 60,
            tracing: false,
        };
    }
    patchLogProcesserRole() {
        const template = this.serverless.service.provider.compiledCloudFormationTemplate;
        // Update lambda dependencies
        template.Resources[this.logProcesserLogicalId].DependsOn.push('ServerlessEsLogsLambdaIAMRole');
        template.Resources[this.logProcesserLogicalId].Properties.Role = {
            'Fn::GetAtt': [
                'ServerlessEsLogsLambdaIAMRole',
                'Arn',
            ],
        };
    }
    cleanupFiles() {
        const dirPath = path_1.default.join(this.serverless.config.servicePath, this.logProcesserDir);
        fs_extra_1.default.removeSync(dirPath);
    }
}
module.exports = ServerlessEsLogsPlugin;
//# sourceMappingURL=index.js.map