# service-disabled

coreo_aws_advisor_alert "cloudtrail-service-disabled" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/cloudtrail-service-disabled.html"
  display_name "Cloudtrail Service is disabled"
  description "CloudTrail logging is not enabled for this region. It should be enabled."
  category "Audit"
  suggested_action "Enable CloudTrail logs"
  level "Warning"
  objectives ["trails"]
  formulas ["count"]
  audit_objects ["trail_list"]
  operators ["=="]
  alert_when [0]
end

coreo_aws_advisor_alert "cloudtrail-trail-with-global" do
  action :define
  service :cloudtrail
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["trails"]
  audit_objects ["trail_list.include_global_service_events"]
  operators ["=="]
  alert_when [true]
  id_map "object.trail_list.name"
end

coreo_aws_advisor_cloudtrail "advise-cloudtrail" do
  action :advise
  alerts ${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}
  regions ${AUDIT_AWS_CLOUDTRAIL_REGIONS}
end

# this is the original notifier
#
coreo_uni_util_notify "advise-cloudtrail-old" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_CLOUDTRAIL_SEND_ON}"
  payload '{"stack name":"PLAN::stack_name",
  "instance name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report }'
  payload_type "json"
  endpoint ({
              :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
            })
end

# this is the new notifier that takes the violations transformed by the jsrunner
#
coreo_uni_util_notify "advise-cloudtrail" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_CLOUDTRAIL_SEND_ON}"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.cloudtrail-aggregate.return'
  payload_type "json"
  endpoint ({
              :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
            })
end

#   "regions":"${AUDIT_AWS_CLOUDTRAIL_REGIONS}",


## Create Notifiers
coreo_uni_util_jsrunner "tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
        {
          :name => "cloudcoreo-jsrunner-commons",
          :version => "1.0.2"
        }       ])
  json_input '{"stack name":"PLAN::stack_name",
                "instance name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations"
                "violations": COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report}'
  function <<-EOH
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditCloudtrail = new CloudCoreoJSRunner(json_input, false, "${AUDIT_AWS_CLOUDTRAIL_ALERT_NO_OWNER_RECIPIENT}", "${AUDIT_AWS_CLOUDTRAIL_OWNER_TAG}");
const notifiers = AuditCloudtrail.getNotifiers();
callback(notifiers);
EOH
end


## Create rollup String
coreo_uni_util_jsrunner "tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array.return'
  function <<-EOH
var rollup_string = "";
for (var entry=0; entry < json_input.length; entry++) {
  console.log(json_input[entry]);
  if (json_input[entry]['endpoint']['to'].length) {
    console.log('got an email to rollup');
    rollup_string = rollup_string + "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
  }
}
callback(rollup_string);
EOH
end


## Send Notifiers
coreo_uni_util_notify "advise-cloudtrail-to-tag-values" do
  action :${AUDIT_AWS_CLOUDTRAIL_OWNERS_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array.return'
end




coreo_uni_util_notify "advise-cloudtrail" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDTRAIL_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_CLOUDTRAIL_SEND_ON}"
  payload '{"stack name":"PLAN::stack_name",
  "instance name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudtrail advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_notify "advise-cloudtrail-rollup" do
  action :${AUDIT_AWS_CLOUDTRAIL_ROLLUP_REPORT}
  type 'email'
  allow_empty true
  send_on 'always'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
number_of_checks: COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_checks
number_of_violations: COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_violations
number_violations_ignored: COMPOSITE::coreo_aws_advisor_cloudtrail.advise-cloudtrail.number_ignored_violations

rollup report:
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDTRAIL_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

