# user-visible engine-powered rule definitions

coreo_aws_rule "cloudtrail-inventory" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Cloudtrail Inventory"
  description "This rule performs an inventory on all trails in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["trails"]
  audit_objects ["object.trail_list.name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.trail_list.name"
end

coreo_aws_rule "cloudtrail-service-disabled" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-service-disabled.html"
  display_name "Cloudtrail Service is Disabled"
  description "CloudTrail logging is not enabled for this region. It should be enabled."
  category "Audit"
  suggested_action "Enable CloudTrail logs for each region."
  level "Low"
  meta_cis_id "2.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.1.12, 3.3.7, 3.3.2"
  objectives ["trails"]
  formulas ["count"]
  audit_objects ["trail_list"]
  operators ["=="]
  raise_when [0]
  id_map "stack.current_region"
end

coreo_aws_rule "cloudtrail-log-file-validating" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-log-file-validating.html"
  display_name "Cloudtrail Log File Validation Disabled"
  description "CloudTrail log file validation is disabled for this trail. It should be enabled"
  category "Audit"
  suggested_action "Enable CloudTrail log file validation for this trail."
  level "Low"
  meta_cis_id "2.2"
  meta_cis_scored "true"
  meta_cis_level "2"
  objectives ["trails"]
  audit_objects ["object.trail_list.log_file_validation_enabled"]
  operators ["=="]
  raise_when [false]
  id_map "stack.current_region"
end

coreo_aws_rule "cloudtrail-logs-cloudwatch" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-logs-cloudwatch.html"
  display_name "Cloudtrail Logs Integrated with CloudWatch"
  description "CloudTrail logs have not attempted delivery to CloudWatch in the last 24 hours. Ensure CloudWatch is integrated"
  category "Audit"
  suggested_action "Integrate CloudWatch with Cloudtrail"
  level "Low"
  meta_cis_id "2.4"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.3.6"
  objectives ["trails", "trail_status"]
  call_modifiers [{}, {:name => "object.trail_list.name"}]
  audit_objects ["", "object.latest_cloud_watch_logs_delivery_time"]
  operators ["", "<"]
  raise_when ["", "1.day.ago"]
  id_map "modifiers.name"
end

# TODO: rules that are service=user should not require objectives,audit_objects,operators,raise_when,id_map

coreo_aws_rule "cloudtrail-no-global-trails" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-trail-with-global.html"
  display_name "Cloudtrail Global Logging is Disabled"
  suggested_action "Enable CloudTrail global service logging in at least one region"
  description "CloudTrail global service logging is not enabled for the selected regions."
  level "Low"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map ""
end

coreo_aws_rule "cloudtrail-logs-encrypted" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-logs-encrypted.html"
  display_name "Verify CloudTrail logs are encrypted at rest using KMS CMKs"
  suggested_action "It is recommended that CloudTrail be configured to use SSE-KMS."
  description "AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs."
  level "Medium"
  meta_cis_id "2.7"
  meta_cis_scored "true"
  meta_cis_level "2"
  meta_nist_171_id "3.3.1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

# end of user-visible content. Remaining resources are system-defined

coreo_aws_rule "cloudtrail-trail-with-global" do
  action :define
  service :cloudtrail
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["trails"]
  audit_objects ["trail_list.include_global_service_events"]
  operators ["=="]
  raise_when [true]
  id_map "stack.current_region"
end

coreo_aws_rule "cloudtrail-inventory-1" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/"
  include_violations_in_count false
  display_name "Inventory CloudTrail"
  description "Inventory CloudTrail"
  category "Inventory"
  level "Internal"
  objectives ["trails"]
  audit_objects ["object.trail_list.name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.trail_list.name"
end

coreo_aws_rule_runner "cloudtrail-inventory-runner" do
  action :run
  service :cloudtrail
  rules ["cloudtrail-inventory-1"]
end

coreo_uni_util_variables "cloudtrail-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.cloudtrail-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.cloudtrail-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.cloudtrail-planwide.results' => 'unset'},
                {'GLOBAL::number_violations' => '0'}
            ])
end

coreo_aws_rule_runner_cloudtrail "advise-cloudtrail" do
  action :run
  rules(${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}.push("cloudtrail-trail-with-global") - ["cloudtrail-log-file-validating"])
  regions ${AUDIT_AWS_CLOUDTRAIL_REGIONS}
end

coreo_aws_rule_runner "advise-cloudtrail-u" do
  action :run
  service :cloudtrail
  rules ["cloudtrail-log-file-validating"] if ${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}.include?("cloudtrail-log-file-validating")
  rules [""] if !(${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}.include?("cloudtrail-log-file-validating"))
end

coreo_uni_util_variables "cloudtrail-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.cloudtrail-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.number_violations'},

            ])
end

coreo_uni_util_jsrunner "cloudtrail-aggregate" do
  action :run
  json_input '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.number_ignored_violations",
  "violations":COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report}'
  function <<-EOH
const alertArrayJSON = "${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}";
const regionArrayJSON = "${AUDIT_AWS_CLOUDTRAIL_REGIONS}";

const alertArray = JSON.parse(alertArrayJSON.replace(/'/g, '"'));
const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'));

let counterForGlobalTrails = 0;
let violationCounter = 0;

function createJSONInputWithNoGlobalTrails() {
    copyViolationInNewJsonInput();
    createNoGlobalTrailViolation();
    copyPropForNewJsonInput();
}

function copyPropForNewJsonInput() {
    newJSONInput['composite name'] = json_input['composite name'];
    newJSONInput['plan name'] = json_input['plan name'];
    newJSONInput['regions'] = regionArrayJSON;
    newJSONInput['number_of_violations'] = violationCounter;
}

function copyViolationInNewJsonInput() {
    newJSONInput['violations'] = {};
    const regionKeys = Object.keys(json_input['violations']);
    violationCounter = json_input['number_of_violations'];
    regionKeys.forEach(regionKey => {
        newJSONInput['violations'][regionKey] = {};
        const objectIdKeys = Object.keys(json_input['violations'][regionKey]);
        objectIdKeys.forEach(objectIdKey => {
            const hasCloudtrailWithGlobal = json_input['violations'][regionKey][objectIdKey]['violations']['cloudtrail-trail-with-global'];
            if (hasCloudtrailWithGlobal) {
                counterForGlobalTrails++;
            } else {
                //violationCounter++;
                newJSONInput['violations'][regionKey][objectIdKey] = json_input['violations'][regionKey][objectIdKey];
            }
        });
    });
}

function createNoGlobalTrailViolation() {
    //const hasCloudtrailNoGlobalInAlertArray = alertArray.indexOf('cloudtrail-no-global-trails') >= 0;
    //if (!counterForGlobalTrails && hasCloudtrailNoGlobalInAlertArray) {
    if (!counterForGlobalTrails) {
        regionArray.forEach(region => {
            violationCounter++;
            const noGlobalsMetadata = {
                'service': 'cloudtrail',
                'link': 'http://kb.cloudcoreo.com/mydoc_cloudtrail-trail-with-global.html',
                'display_name': 'Cloudtrail global logging is disabled',
                'description': 'CloudTrail global service logging is not enabled for the selected regions.',
                'category': 'Audit',
                'suggested_action': 'Enable CloudTrail global service logging in at least one region',
                'level': 'Warning',
                'region': region
            };
            const noGlobalsAlert = {
                violations: {'cloudtrail-no-global-trails': noGlobalsMetadata },
                tags: []
            };
            setValueForNewJSONInput(region, noGlobalsMetadata, noGlobalsAlert);
        });
    }
}

function setValueForNewJSONInput(region, noGlobalsMetadata, noGlobalsAlert) {
    try {
          if (Object.keys(newJSONInput['violations'][region])) {};
      } catch (e) {
          newJSONInput['violations'][region] = {}
      }
    const regionKeys = Object.keys(newJSONInput['violations'][region]);
    var found = false;
    regionKeys.forEach(regionKey => {
        if (newJSONInput['violations'][regionKey]) {
            found = true;
            if (newJSONInput['violations'][regionKey][region]) {
                newJSONInput['violations'][regionKey][region]['violations']['cloudtrail-no-global-trails'] = noGlobalsMetadata;
            } else {
                newJSONInput['violations'][regionKey][region] = noGlobalsAlert;
            }
        }
        if (!found) {
            newJSONInput['violations'][regionKey] = {};
            newJSONInput['violations'][regionKey][region] = {};
            newJSONInput['violations'][regionKey][region]['violations'] = {};
            newJSONInput['violations'][regionKey][region]['tags'] = [];
            newJSONInput['violations'][regionKey][region]['violations']['cloudtrail-no-global-trails'] = noGlobalsMetadata;
        }
    });
}

const newJSONInput = {};

createJSONInputWithNoGlobalTrails();
coreoExport('violation_counter', violationCounter);

callback(newJSONInput['violations']);
  EOH
end

coreo_uni_util_variables "cloudtrail-update-planwide-2" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'},
                {'COMPOSITE::coreo_uni_util_variables.cloudtrail-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.violation_counter'}
            ])
end

coreo_uni_util_jsrunner "cis27-processor" do
  action (("${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}".include?("cloudtrail-logs-encrypted")) ? :run : :nothing)
  json_input (("${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}".include?("cloudtrail-logs-encrypted")) ? '[COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report, COMPOSITE::coreo_aws_rule_runner.cloudtrail-inventory-runner.report]' : '[]')
  function <<-'EOH'
  const ruleMetaJSON = {
      'cloudtrail-logs-encrypted': COMPOSITE::coreo_aws_rule.cloudtrail-logs-encrypted.inputs
  };
  const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count'];
  const ruleMeta = {};

  Object.keys(ruleMetaJSON).forEach(rule => {
      const flattenedRule = {};
      ruleMetaJSON[rule].forEach(input => {
          if (ruleInputsToKeep.includes(input.name))
              flattenedRule[input.name] = input.value;
      })
      ruleMeta[rule] = flattenedRule;
  })

  const USER_RULE = 'cloudtrail-logs-encrypted'
  const INVENTORY_RULE = 'cloudtrail-inventory-1';

  const regionArrayJSON = "${AUDIT_AWS_CLOUDTRAIL_REGIONS}";
  const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'))

  const inventory = json_input[1];
  var json_output = json_input[0]

  const violations = copyViolationInNewJsonInput(regionArray, json_output);

  regionArray.forEach(region => {
      if (!inventory[region]) return;

      const trails = Object.keys(inventory[region]);

      trails.forEach(trail => {
          if (!inventory[region][trail]['violations'][INVENTORY_RULE] || !verifyTrailContainsKMSkey(inventory[region][trail]['violations'][INVENTORY_RULE]['result_info'])){
                updateOutputWithResults(region, trail, inventory[region][trail]['violations'][INVENTORY_RULE]['result_info'], USER_RULE);
          }
      })
  })

  function copyViolationInNewJsonInput(regions, input) {
      const output = {};
      regions.forEach(regionKey => {
          if (!input[regionKey]) {
            output[regionKey] = {};
          } else {
            output[regionKey] = input[regionKey]
          }
      });
      return output;
  }

  function updateOutputWithResults(region, objectID, objectDetails, rule) {
      if (!violations[region][objectID]) {
          violations[region][objectID] = {};
          violations[region][objectID]['violator_info'] = objectDetails;
      }
      if (!violations[region][objectID]['violations']) {
          violations[region][objectID]['violations'] = {};
      }

      var rule_value = JSON.parse(JSON.stringify(ruleMeta[rule]));
      rule_value['region'] = region
      violations[region][objectID]['violations'][rule] = rule_value;
  }

  function verifyTrailContainsKMSkey(results) {
      let kmsKeyExist = false
      results.forEach(result => {
          if ("kms_key_id" in result['object']){
            kmsKeyExist = true
          }
      })

      return kmsKeyExist;
  }

  callback(violations);
EOH
end

coreo_uni_util_variables "cloudtrail-update-planwide-3" do
  action   action (("${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}".include?("cloudtrail-logs-encrypted")) ? :set : :nothing)
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis27-processor.return'}
            ])
end

coreo_uni_util_jsrunner "cloudtrail-tags-to-notifiers-array" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.9.7-beta22"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               } ])
  json_input '{ "compositeName":"PLAN::stack_name",
                "planName":"PLAN::name",
                "cloudAccountName": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report}'
  function <<-EOH

const compositeName = json_input.compositeName;
const planName = json_input.planName;
const cloudAccount = json_input.cloudAccountName;
const cloudObjects = json_input.violations;


const NO_OWNER_EMAIL = "${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_CLOUDTRAIL_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_CLOUDTRAIL_SEND_ON}";
const alertListArray = ${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST};

const ruleInputs = {};
let userSuppression;
let userSchemes;

const fs = require('fs');
const yaml = require('js-yaml');

function setSuppression() {
  try {
    userSuppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
    console.log(`Error reading suppression.yaml file`);
    userSuppression = [];
  }
  coreoExport('suppression', JSON.stringify(userSuppression));
}

function setTable() {
  try {
    userSchemes = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
    console.log(`Error reading table.yaml file`);
    userSchemes = {};
  }
  coreoExport('table', JSON.stringify(userSchemes));
}
setSuppression();
setTable();
const argForConfig = {
    NO_OWNER_EMAIL, cloudObjects, userSuppression, OWNER_TAG,
    userSchemes, alertListArray, ruleInputs, ALLOW_EMPTY,
    SEND_ON, cloudAccount, compositeName, planName
}


function createConfig(argForConfig) {
    let JSON_INPUT = {
        compositeName: argForConfig.compositeName,
        planName: argForConfig.planName,
        violations: argForConfig.cloudObjects,
        userSchemes: argForConfig.userSchemes,
        userSuppression: argForConfig.userSuppression,
        alertList: argForConfig.alertListArray,
        disabled: argForConfig.ruleInputs,
        cloudAccount: argForConfig.cloudAccount
    };
    let SETTINGS = {
        NO_OWNER_EMAIL: argForConfig.NO_OWNER_EMAIL,
        OWNER_TAG: argForConfig.OWNER_TAG,
        ALLOW_EMPTY: argForConfig.ALLOW_EMPTY, SEND_ON: argForConfig.SEND_ON,
        SHOWN_NOT_SORTED_VIOLATIONS_COUNTER: false
    };
    return {JSON_INPUT, SETTINGS};
}

const {JSON_INPUT, SETTINGS} = createConfig(argForConfig);
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');

const emails = CloudCoreoJSRunner.createEmails(JSON_INPUT, SETTINGS);
const suppressionJSON = CloudCoreoJSRunner.createJSONWithSuppress(JSON_INPUT, SETTINGS);

coreoExport('JSONReport', JSON.stringify(suppressionJSON));
coreoExport('report', JSON.stringify(suppressionJSON['violations']));

callback(emails);
  EOH
end

coreo_uni_util_variables "cloudtrail-update-planwide-4" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.cloudtrail-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-to-notifiers-array.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-to-notifiers-array.report'},
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-to-notifiers-array.table'}
          ])
end

coreo_uni_util_jsrunner "cloudtrail-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-to-notifiers-array.return'
  function <<-EOH

const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-cloudtrail-to-tag-values" do
  action((("${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-cloudtrail-rollup" do
  action((("${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_CLOUDTRAIL_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_CLOUDTRAIL_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'PLAN::stack_name New Rollup Report for PLAN::name plan from CloudCoreo'
  })
end
