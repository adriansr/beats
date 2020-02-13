// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

var processor = require("processor");
var console   = require("console");


// PipelineBuilder to aid debugging of pipelines during development.
function PipelineBuilder(pipelineName, debug) {
    this.pipeline = new processor.Chain();
    this.add = function (processor) {
        this.pipeline = this.pipeline.Add(processor);
    };
    this.Add = function (name, processor) {
        this.add(processor);
        if (debug) {
            this.add(makeLogEvent("after " + pipelineName + "/" + name));
        }
    };
    this.Build = function () {
        if (debug) {
            this.add(makeLogEvent(pipelineName + "processing done"));
        }
        return this.pipeline.Build();
    };
    if (debug) {
        this.add(makeLogEvent(pipelineName + ": begin processing event"));
    }
}

// logEvent(msg)
//
// Processor that logs the current value of evt to console.debug.
function makeLogEvent(msg) {
    return function (evt) {
        console.debug(msg + " :" +  JSON.stringify(evt, null, 4));
    };
}

// makeConditional({condition:expr, result1:processor|expr, [...]})
//
// Processor that selects which processor to run depending on the result of
// evaluating a _condition_. Result can be boolean (if-else equivalent) or any
// other value (switch equivalent). Unspecified values are a no-op.
function makeConditional(options) {
    return function (evt) {
        var branch = options[options.condition(evt)] || function(evt){};
        return (typeof branch === "function" ? branch : branch.Run)(evt);
    };
}

// makeMapper({from:field, to:field, default:value mappings:{orig: new, [...]}})
//
// Processor that sets _to_ field from a mapping of _from_ field's value.
function makeMapper(options) {
    return function (evt) {
        var key = evt.Get(options.from);
        if (key == null && options.skip_missing) return;
        if (options.lowercase && typeof key == "string") {
            key = key.toLowerCase();
        }
        var value = options.default;
        if (key in options.mappings) {
            value = options.mappings[key];
        } else if (typeof value === "function") {
            value = value(key);
        }
        if (value != null) {
            evt.Put(options.to, value);
        }
    };
}

function validFieldName(s) {
    // Remove spaces and dots from keys.
    return s.replace(/[\ \.]/g, '_')
}

function makeDictFromKVArray(options) {
    return function(evt) {
        var src = evt.Get(options.from);
        var dict = {};
        if (src == null || !(src instanceof Array)) return;
        for (var i=0; i < src.length; i++) {
            var name, value;
            if (src[i] == null
                || (name=src[i].Name) == null
                || (value=src[i].Value) == null) continue;
            name = validFieldName(name);
            if (name in dict) {
                if (dict[name] instanceof Array) {
                    dict[name].push(value);
                } else {
                    dict[name] = [value];
                }
            } else {
                dict[name] = value;
            }
        }
        evt.Put(options.to, dict);
    }
}

function makeDictFromModifiedPropertyArray(options) {
    return function(evt) {
        var src = evt.Get(options.from);
        var dict = {};
        if (src == null || !(src instanceof Array)) return;
        for (var i=0; i < src.length; i++) {
            var name, newValue, oldValue;
            if (src[i] == null
                || (name=src[i].Name) == null
                || (newValue=src[i].NewValue) == null
                || (oldValue=src[i].OldValue)) continue;
            name = validFieldName(name);
            if (name in dict) {
                if (dict[name].NewValue instanceof Array) {
                    dict[name].NewValue.push(newValue);
                    dict[name].OldValue.push(oldValue);
                } else {
                    dict[name].NewValue = [newValue];
                    dict[name].OldValue = [oldValue];
                }
            } else {
                dict[name] = {
                    NewValue: newValue,
                    OldValue: oldValue,
                };
            }
        }
        evt.Put(options.to, dict);
    }
}

function exchangeAdminSchema(debug) {
    var builder = new PipelineBuilder("o365.audit.ExchangeAdmin", debug);
    builder.Add("saveFields", new processor.Convert({
        fields: [
            {from: 'o365audit.OrganizationName', to: 'organization.name'},
            {from: 'o365audit.OriginatingServer', to: 'server.address'},
        ],
        ignore_missing: true,
        fail_on_error: false
    }));
    return builder.Build();
}

function azureADLogonSchema(debug) {
    var builder = new PipelineBuilder("o365.audit.AzureActiveDirectory", debug);
    builder.Add("setEventAuthFields", function(evt){
       evt.Put("event.category", "authentication");
       var outcome = evt.Get("event.outcome");
       if (outcome != null && outcome !== "unknown") {
           evt.Put("event.type", "authentication_" + outcome);
       }
    });
    return builder.Build();
}

function sharePointFileOperationSchema(debug) {
    var builder = new PipelineBuilder("o365.audit.SharePointFileOperation", debug);
    builder.Add("saveFields", new processor.Convert({
        fields: [
            {from: 'o365audit.ObjectId', to: 'url.original'},
            {from: 'o365audit.SourceRelativeUrl', to: 'file.directory'},
            {from: 'o365audit.SourceFileName', to: 'file.name'},
            {from: 'o365audit.SourceFileExtension', to: 'file.extension'},
        ],
        ignore_missing: true,
        fail_on_error: false
    }));
    builder.Add("setEventCategory", new processor.AddFields({
        target: 'event',
        fields: {
            category: 'file',
        },
    }));
    builder.Add("mapEventType", makeMapper({
        from: 'o365audit.Operation',
        to: 'event.type',
        mappings: {
            'FileAccessed': 'access',
            'FileDeleted': 'deletion',
            'FileDownloaded': 'access',
            'FileModified': 'change',
            'FileMoved': 'change',
            'FileRenamed': 'change',
            'FileRestored': 'change',
            'FileUploaded': 'creation',
            'FolderCopied': 'creation',
            'FolderCreated': 'creation',
            'FolderDeleted': 'deletion',
            'FolderModified': 'change',
            'FolderMoved': 'change',
            'FolderRenamed': 'change',
            'FolderRestored': 'change',
        },
    }));
    return builder.Build();
}

function exchangeMailboxSchema(debug) {
    var builder = new PipelineBuilder("o365.audit.SharePointFileOperation", debug);
    builder.Add("saveFields", new processor.Convert({
        fields: [
            {from: 'o365audit.MailboxOwnerUPN', to: 'user.email'},
            {from: 'o365audit.LogonUserSid', to: 'user.id'},
            {from: 'o365audit.LogonUserDisplayName', to: 'user.full_name'},
            {from: 'o365audit.OrganizationName', to: 'organization.name'},
            {from: 'o365audit.OriginatingServer', to: 'server.address'},
            {from: 'o365audit.ClientIPAddress', to: 'client.address'},
            {from: 'o365audit.ClientProcessName', to: 'process.name'},
        ],
        ignore_missing: true,
        fail_on_error: false
    }));
    return builder.Build();
}

function AuditProcessor(debug) {
    var builder = new PipelineBuilder("o365.audit", debug);

    builder.Add("cleanupNulls", function(event) {
        ["o365audit.ClientIP"].forEach(function(field) {
            var value = event.Get(field);
            if (value === "null" || value === "<null>") {
                event.Delete(field);
            }
        })
    });
    builder.Add("convertCommonAuditRecordFields", new processor.Convert({
        fields: [
            {from: "o365audit.Id", to: "event.id"},
            {from: "o365audit.ClientIP", to: "client.address"},
            {from: "o365audit.UserKey", to: "user.hash"},
            {from: "o365audit.UserId", to: "user.id"},
            {from: "o365audit.Workload", to: "event.provider"},
            {from: "o365audit.Operation", to: "event.action"},
            {from: "o365audit.OrganizationId", to: "organization.id"},
            // Extra common fields:
            {from: "o365audit.UserAgent", to: "user_agent.original"},
        ],
        // TODO: should? // mode: "rename",
        ignore_missing: true,
        fail_on_error: false
    }));
    builder.Add("mapEventType", makeMapper({
        from: 'o365audit.RecordType',
        to: 'event.code',
        // Keep recordType for unknown mappings.
        default: function(recordType) {
            return recordType;
        },
        mappings: {
            1: 'ExchangeAdmin', // Events from the Exchange admin audit log.
            2: 'ExchangeItem', // Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.
            3: 'ExchangeItemGroup', // Events from an Exchange mailbox audit log for actions that can be performed on multiple items, such as moving or deleted one or more email messages.
            4: 'SharePoint', // SharePoint events.
            6: 'SharePointFileOperation', // SharePoint file operation events.
            8: 'AzureActiveDirectory', // Azure Active Directory events.
            9: 'AzureActiveDirectoryAccountLogon', // Azure Active Directory OrgId logon events (deprecating).
            10: 'DataCenterSecurityCmdlet', // Data Center security cmdlet events.
            11: 'ComplianceDLPSharePoint', // Data loss protection (DLP) events in SharePoint and OneDrive for Business.
            12: 'Sway', // Events from the Sway service and clients.
            13: 'ComplianceDLPExchange', // Data loss protection (DLP) events in Exchange, when configured via Unified DLP Policy. DLP events based on Exchange Transport Rules are not supported.
            14: 'SharePointSharingOperation', // SharePoint sharing events.
            15: 'AzureActiveDirectoryStsLogon', // Secure Token Service (STS) logon events in Azure Active Directory.
            18: 'SecurityComplianceCenterEOPCmdlet', // Admin actions from the Security & Compliance Center.
            20: 'PowerBIAudit', // Power BI events.
            21: 'CRM', // Microsoft CRM events.
            22: 'Yammer', // Yammer events.
            23: 'SkypeForBusinessCmdlets', // Skype for Business events.
            24: 'Discovery', // Events for eDiscovery activities performed by running content searches and managing eDiscovery cases in the Security & Compliance Center.
            25: 'MicrosoftTeams', // Events from Microsoft Teams.
            28: 'ThreatIntelligence', // Phishing and malware events from Exchange Online Protection and Office 365 Advanced Threat Protection.
            30: 'MicrosoftFlow', // Microsoft Power Automate (formerly called Microsoft Flow) events.
            31: 'AeD', // Advanced eDiscovery events.
            32: 'MicrosoftStream', // Microsoft Stream events.
            33: 'ComplianceDLPSharePointClassification', // Events related to DLP classification in SharePoint.
            35: 'Project', // Microsoft Project events.
            36: 'SharePointListOperation', // SharePoint List events.
            38: 'DataGovernance', // Events related to retention policies and retention labels in the Security & Compliance Center
            40: 'SecurityComplianceAlerts', // Security and compliance alert signals.
            41: 'ThreatIntelligenceUrl', // Safe links time-of-block and block override events from Office 365 Advanced Threat Protection.
            42: 'SecurityComplianceInsights', // Events related to insights and reports in the Office 365 security and compliance center.
            44: 'WorkplaceAnalytics', // Workplace Analytics events.
            45: 'PowerAppsApp', // Power Apps events.
            47: 'ThreatIntelligenceAtpContent', // Phishing and malware events for files in SharePoint, OneDrive for Business, and Microsoft Teams from Office 365 Advanced Threat Protection.
            49: 'TeamsHealthcare', // Events related to the Patients application in Microsoft Teams for Healthcare.
            52: 'DataInsightsRestApiAudit', // Data Insights REST API events.
            54: 'SharePointListItemOperation', // SharePoint list item events.
            55: 'SharePointContentTypeOperation', // SharePoint list content type events.
            56: 'SharePointFieldOperation', // SharePoint list field events.
            64: 'AirInvestigation', // Automated incident response (AIR) events.
            66: 'MicrosoftForms', // Microsoft Forms events.
        },
    }));
    builder.Add("mapEventOutcome", makeMapper({
        from: 'o365audit.ResultStatus',
        to: 'event.outcome',
        lowercase: true,
        default: 'unknown',
        skip_missing: true,
        mappings: {
            'success': 'success', // This one is necessary to map Success
            'succeeded': 'success',
            'partiallysucceeded': 'success',
            'true': 'success',
            'failed': 'failure',
            'false': 'failure',
        },
    }));
    builder.Add("setEventKind", new processor.AddFields({
        target: 'event',
        fields: {
            kind: 'event',
        },
    }));
    builder.Add("setUserFieldsFromId", new processor.Dissect({
        tokenizer: "%{name}@%{domain}",
        field: "user.id",
        target_prefix: "user",
        'when.contains.user.id': '@',
    }));
    builder.Add("makeParametersDict", makeDictFromKVArray({
        from: 'o365audit.Parameters',
        to: 'o365audit.Parameters',
    }));
    builder.Add("makeExtendedPropertiesDict", makeDictFromKVArray({
        from: 'o365audit.ExtendedProperties',
        to: 'o365audit.ExtendedProperties',
    }));
    builder.Add("makeModifiedPropertyDict", makeDictFromModifiedPropertyArray({
        from: 'o365audit.ModifiedProperties',
        to: 'o365audit.ModifiedProperties',
    }));

    // Populate event specific fields.
    builder.Add("productSpecific", makeConditional({
     condition: function(event) {
         return event.Get("event.code");
     },
     'ExchangeAdmin': exchangeAdminSchema(debug).Run,
     'ExchangeItem': exchangeMailboxSchema(debug).Run,
     'AzureActiveDirectoryStsLogon': azureADLogonSchema(debug).Run,
     'SharePointFileOperation': sharePointFileOperationSchema(debug).Run,
    }));

    // Copy the source/destination.address to source/destination.ip if they are
    // valid IP addresses.
    builder.Add("copyAddressFields", new processor.Convert({
        fields: [
            {from: "source.address", to: "source.ip", type: "ip"},
            {from: "destination.address", to: "destination.ip", type: "ip"},
            {from: "client.address", to: "client.ip", type: "ip"},
            {from: "server.address", to: "server.ip", type: "ip"},
        ],
        ignore_missing: true,
        fail_on_error: false
    }));

    builder.Add("setNetworkType", function(event) {
        var ip = event.Get("client.ip");
        if (!ip) {
            return;
        }

        if (ip.indexOf(".") !== -1) {
            event.Put("network.type", "ipv4");
        } else {
            event.Put("network.type", "ipv6");
        }
    });

    builder.Add("setRelatedIP", function(event) {
        ["source.ip", "destination.ip"].forEach(function(field) {
            var val = event.Get(field);
            if (val) {
                event.AppendTo("related.ip", val);
            }
        })
    });

    var chain = builder.Build();
    return {
        process: chain.Run
    };
}


var audit;

// Register params from configuration.
function register(params) {
    audit = new AuditProcessor(params.debug);
}

function process(evt) {
    return audit.process(evt);
}
