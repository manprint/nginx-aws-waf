# WAF lab matrix — 2026-11-26 (UTC)

## 1. Per site: actions, AWS default actions, disagreements
| site_id | total | allow | block | count_ | aws_allow | aws_block | disagree | dis_backend | dis_website | dis_static | dis_realtime | dis_other |
|:-|-:|-:|-:|-:|-:|-:|-:|-:|-:|-:|-:|-:|
|  | 6681 | 6681 | 0 | 0 | 6681 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| __default__ | 49689 | 49634 | 55 | 0 | 49632 | 57 | 10 | 0 | 0 | 0 | 0 | 10 |
| allowlist | 20 | 11 | 9 | 0 | 20 | 0 | 9 | 0 | 0 | 0 | 0 | 9 |
| demo | 461615 | 461145 | 470 | 0 | 461140 | 475 | 5 | 0 | 0 | 0 | 0 | 5 |
| shadow | 10 | 10 | 0 | 0 | 1 | 9 | 9 | 0 | 0 | 0 | 0 | 9 |
| shop12 | 7879 | 2369 | 5510 | 0 | 2340 | 5539 | 29 | 29 | 0 | 0 | 0 | 0 |
| shop14 | 15903 | 8576 | 7327 | 0 | 8547 | 7356 | 29 | 29 | 0 | 0 | 0 | 0 |
| shop16 | 21016 | 12412 | 8604 | 0 | 12383 | 8633 | 29 | 29 | 0 | 0 | 0 | 0 |
| shop18 | 23118 | 13660 | 9458 | 0 | 13635 | 9483 | 25 | 25 | 0 | 0 | 0 | 0 |
| strict | 40 | 13 | 27 | 0 | 40 | 0 | 27 | 0 | 0 | 0 | 0 | 27 |
| tuned | 83 | 41 | 42 | 0 | 9 | 74 | 32 | 0 | 0 | 0 | 0 | 32 |

## 2. Per rule: matches per site and configured action
| rule_group | rule_name | site_id | configured_action | matches |
|:-|:-|:-|:-|-:|
| AWSManagedRulesAmazonIpReputationList | AWSManagedIPReputationList | __default__ | BLOCK | 2 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedIPReputationList | demo | BLOCK | 18 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedIPReputationList | shop12 | BLOCK | 10 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedIPReputationList | shop14 | BLOCK | 10 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedIPReputationList | shop16 | BLOCK | 10 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedIPReputationList | shop18 | BLOCK | 10 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedReconnaissanceList | __default__ | BLOCK | 1 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedReconnaissanceList | demo | BLOCK | 9 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedReconnaissanceList | shop12 | BLOCK | 5 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedReconnaissanceList | shop14 | BLOCK | 5 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedReconnaissanceList | shop16 | BLOCK | 5 |
| AWSManagedRulesAmazonIpReputationList | AWSManagedReconnaissanceList | shop18 | BLOCK | 5 |
| AWSManagedRulesAnonymousIpList | AnonymousIPList | __default__ | BLOCK | 1 |
| AWSManagedRulesAnonymousIpList | AnonymousIPList | strict | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_BODY | __default__ | BLOCK | 3 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_BODY | demo | BLOCK | 18 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_BODY | shop12 | COUNT | 115 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_BODY | shop14 | COUNT | 223 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_BODY | shop16 | COUNT | 324 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_BODY | shop18 | COUNT | 377 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_BODY | tuned | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_COOKIE | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_COOKIE | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_COOKIE | shop12 | BLOCK | 11 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_COOKIE | shop14 | BLOCK | 13 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_COOKIE | shop16 | BLOCK | 15 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_COOKIE | shop18 | BLOCK | 15 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_QUERYARGUMENTS | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_QUERYARGUMENTS | demo | BLOCK | 13 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_QUERYARGUMENTS | shop12 | BLOCK | 37 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_QUERYARGUMENTS | shop14 | BLOCK | 468 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_QUERYARGUMENTS | shop16 | BLOCK | 823 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_QUERYARGUMENTS | shop18 | BLOCK | 1047 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_URIPATH | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_URIPATH | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_URIPATH | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_URIPATH | shop14 | BLOCK | 82 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_URIPATH | shop16 | BLOCK | 153 |
| AWSManagedRulesCommonRuleSet | CrossSiteScripting_URIPATH | shop18 | BLOCK | 177 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_BODY | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_BODY | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_BODY | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_BODY | shop14 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_BODY | shop16 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_BODY | shop18 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_COOKIE | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_COOKIE | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_COOKIE | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_COOKIE | shop14 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_COOKIE | shop16 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_COOKIE | shop18 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_QUERYARGUMENTS | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_QUERYARGUMENTS | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_QUERYARGUMENTS | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_QUERYARGUMENTS | shop14 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_QUERYARGUMENTS | shop16 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_QUERYARGUMENTS | shop18 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_URIPATH | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_URIPATH | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_URIPATH | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_URIPATH | shop14 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_URIPATH | shop16 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | EC2MetaDataSSRF_URIPATH | shop18 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | GenericLFI_BODY | __default__ | BLOCK | 2 |
| AWSManagedRulesCommonRuleSet | GenericLFI_BODY | demo | BLOCK | 18 |
| AWSManagedRulesCommonRuleSet | GenericLFI_BODY | shop12 | BLOCK | 112 |
| AWSManagedRulesCommonRuleSet | GenericLFI_BODY | shop14 | BLOCK | 228 |
| AWSManagedRulesCommonRuleSet | GenericLFI_BODY | shop16 | BLOCK | 330 |
| AWSManagedRulesCommonRuleSet | GenericLFI_BODY | shop18 | BLOCK | 378 |
| AWSManagedRulesCommonRuleSet | GenericLFI_QUERYARGUMENTS | __default__ | BLOCK | 2 |
| AWSManagedRulesCommonRuleSet | GenericLFI_QUERYARGUMENTS | demo | BLOCK | 18 |
| AWSManagedRulesCommonRuleSet | GenericLFI_QUERYARGUMENTS | shop12 | BLOCK | 86 |
| AWSManagedRulesCommonRuleSet | GenericLFI_QUERYARGUMENTS | shop14 | BLOCK | 578 |
| AWSManagedRulesCommonRuleSet | GenericLFI_QUERYARGUMENTS | shop16 | BLOCK | 958 |
| AWSManagedRulesCommonRuleSet | GenericLFI_QUERYARGUMENTS | shop18 | BLOCK | 1188 |
| AWSManagedRulesCommonRuleSet | GenericLFI_URIPATH | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | GenericLFI_URIPATH | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | GenericLFI_URIPATH | shop12 | BLOCK | 21 |
| AWSManagedRulesCommonRuleSet | GenericLFI_URIPATH | shop14 | BLOCK | 156 |
| AWSManagedRulesCommonRuleSet | GenericLFI_URIPATH | shop16 | BLOCK | 248 |
| AWSManagedRulesCommonRuleSet | GenericLFI_URIPATH | shop18 | BLOCK | 359 |
| AWSManagedRulesCommonRuleSet | GenericRFI_BODY | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | GenericRFI_BODY | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | GenericRFI_BODY | shop12 | COUNT | 11 |
| AWSManagedRulesCommonRuleSet | GenericRFI_BODY | shop14 | COUNT | 15 |
| AWSManagedRulesCommonRuleSet | GenericRFI_BODY | shop16 | COUNT | 15 |
| AWSManagedRulesCommonRuleSet | GenericRFI_BODY | shop18 | COUNT | 15 |
| AWSManagedRulesCommonRuleSet | GenericRFI_QUERYARGUMENTS | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | GenericRFI_QUERYARGUMENTS | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | GenericRFI_QUERYARGUMENTS | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | GenericRFI_QUERYARGUMENTS | shop14 | BLOCK | 32 |
| AWSManagedRulesCommonRuleSet | GenericRFI_QUERYARGUMENTS | shop16 | BLOCK | 32 |
| AWSManagedRulesCommonRuleSet | GenericRFI_QUERYARGUMENTS | shop18 | BLOCK | 33 |
| AWSManagedRulesCommonRuleSet | GenericRFI_URIPATH | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | GenericRFI_URIPATH | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | GenericRFI_URIPATH | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | GenericRFI_URIPATH | shop14 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | GenericRFI_URIPATH | shop16 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | GenericRFI_URIPATH | shop18 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | NoUserAgent_HEADER | __default__ | BLOCK | 6 |
| AWSManagedRulesCommonRuleSet | NoUserAgent_HEADER | demo | BLOCK | 52 |
| AWSManagedRulesCommonRuleSet | NoUserAgent_HEADER | shadow | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | NoUserAgent_HEADER | shop12 | BLOCK | 6 |
| AWSManagedRulesCommonRuleSet | NoUserAgent_HEADER | shop14 | BLOCK | 6 |
| AWSManagedRulesCommonRuleSet | NoUserAgent_HEADER | shop16 | BLOCK | 6 |
| AWSManagedRulesCommonRuleSet | NoUserAgent_HEADER | shop18 | BLOCK | 6 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_QUERYARGUMENTS | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_QUERYARGUMENTS | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_QUERYARGUMENTS | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_QUERYARGUMENTS | shop14 | BLOCK | 16 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_QUERYARGUMENTS | shop16 | BLOCK | 25 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_QUERYARGUMENTS | shop18 | BLOCK | 29 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_URIPATH | __default__ | BLOCK | 2 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_URIPATH | __default__ | COUNT | 1 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_URIPATH | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_URIPATH | shop12 | BLOCK | 11 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_URIPATH | shop14 | BLOCK | 379 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_URIPATH | shop16 | BLOCK | 503 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_URIPATH | shop18 | BLOCK | 551 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_URIPATH | tuned | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | RestrictedExtensions_URIPATH | tuned | COUNT | 9 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_BODY | __default__ | BLOCK | 3 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_BODY | __default__ | COUNT | 5 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_BODY | demo | BLOCK | 28 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_BODY | shop12 | COUNT | 37 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_BODY | shop14 | COUNT | 47 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_BODY | shop16 | COUNT | 53 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_BODY | shop18 | COUNT | 60 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_BODY | tuned | COUNT | 38 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_Cookie_HEADER | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_Cookie_HEADER | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_Cookie_HEADER | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_Cookie_HEADER | shop14 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_Cookie_HEADER | shop16 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_Cookie_HEADER | shop18 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_QUERYSTRING | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_QUERYSTRING | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_QUERYSTRING | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_QUERYSTRING | shop14 | BLOCK | 6 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_QUERYSTRING | shop16 | BLOCK | 7 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_QUERYSTRING | shop18 | BLOCK | 7 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_URIPATH | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_URIPATH | demo | BLOCK | 9 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_URIPATH | shop12 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_URIPATH | shop14 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_URIPATH | shop16 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | SizeRestrictions_URIPATH | shop18 | BLOCK | 5 |
| AWSManagedRulesCommonRuleSet | UserAgent_BadBots_HEADER | __default__ | BLOCK | 1 |
| AWSManagedRulesCommonRuleSet | UserAgent_BadBots_HEADER | demo | BLOCK | 13 |
| AWSManagedRulesCommonRuleSet | UserAgent_BadBots_HEADER | shop12 | BLOCK | 4919 |
| AWSManagedRulesCommonRuleSet | UserAgent_BadBots_HEADER | shop14 | BLOCK | 4919 |
| AWSManagedRulesCommonRuleSet | UserAgent_BadBots_HEADER | shop16 | BLOCK | 4919 |
| AWSManagedRulesCommonRuleSet | UserAgent_BadBots_HEADER | shop18 | BLOCK | 4919 |
| AWSManagedRulesKnownBadInputsRuleSet | ExploitablePaths_URIPATH | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | ExploitablePaths_URIPATH | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | ExploitablePaths_URIPATH | shop12 | BLOCK | 15 |
| AWSManagedRulesKnownBadInputsRuleSet | ExploitablePaths_URIPATH | shop14 | BLOCK | 27 |
| AWSManagedRulesKnownBadInputsRuleSet | ExploitablePaths_URIPATH | shop16 | BLOCK | 43 |
| AWSManagedRulesKnownBadInputsRuleSet | ExploitablePaths_URIPATH | shop18 | BLOCK | 59 |
| AWSManagedRulesKnownBadInputsRuleSet | Host_localhost_HEADER | __default__ | BLOCK | 2 |
| AWSManagedRulesKnownBadInputsRuleSet | Host_localhost_HEADER | demo | BLOCK | 54 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_BODY | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_BODY | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_BODY | shop12 | BLOCK | 27 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_BODY | shop14 | BLOCK | 35 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_BODY | shop16 | BLOCK | 39 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_BODY | shop18 | BLOCK | 45 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_HEADER | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_HEADER | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_HEADER | shop12 | BLOCK | 7 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_HEADER | shop14 | BLOCK | 7 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_HEADER | shop16 | BLOCK | 7 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_HEADER | shop18 | BLOCK | 7 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_QUERYSTRING | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_QUERYSTRING | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_QUERYSTRING | shop12 | BLOCK | 23 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_QUERYSTRING | shop14 | BLOCK | 28 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_QUERYSTRING | shop16 | BLOCK | 33 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_QUERYSTRING | shop18 | BLOCK | 35 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_URIPATH | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_URIPATH | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_URIPATH | shop12 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_URIPATH | shop14 | BLOCK | 10 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_URIPATH | shop16 | BLOCK | 15 |
| AWSManagedRulesKnownBadInputsRuleSet | JavaDeserializationRCE_URIPATH | shop18 | BLOCK | 17 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_BODY | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_BODY | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_BODY | shop12 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_BODY | shop14 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_BODY | shop16 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_BODY | shop18 | BLOCK | 54 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_HEADER | __default__ | BLOCK | 3 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_HEADER | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_HEADER | shop12 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_HEADER | shop14 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_HEADER | shop16 | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_HEADER | shop18 | BLOCK | 21 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_HEADER | tuned | BLOCK | 18 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_QUERYSTRING | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_QUERYSTRING | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_QUERYSTRING | shop12 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_QUERYSTRING | shop14 | BLOCK | 7 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_QUERYSTRING | shop16 | BLOCK | 12 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_QUERYSTRING | shop18 | BLOCK | 23 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_URIPATH | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_URIPATH | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_URIPATH | shop12 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_URIPATH | shop14 | BLOCK | 6 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_URIPATH | shop16 | BLOCK | 7 |
| AWSManagedRulesKnownBadInputsRuleSet | Log4JRCE_URIPATH | shop18 | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | PROPFIND_METHOD | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | PROPFIND_METHOD | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | PROPFIND_METHOD | shop12 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | PROPFIND_METHOD | shop14 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | PROPFIND_METHOD | shop16 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | PROPFIND_METHOD | shop18 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | ReactJSRCE_BODY | __default__ | BLOCK | 1 |
| AWSManagedRulesKnownBadInputsRuleSet | ReactJSRCE_BODY | demo | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | ReactJSRCE_BODY | shop12 | BLOCK | 5 |
| AWSManagedRulesKnownBadInputsRuleSet | ReactJSRCE_BODY | shop14 | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | ReactJSRCE_BODY | shop16 | BLOCK | 9 |
| AWSManagedRulesKnownBadInputsRuleSet | ReactJSRCE_BODY | shop18 | BLOCK | 9 |
| AWSManagedRulesSQLiRuleSet | SQLi_BODY | __default__ | BLOCK | 1 |
| AWSManagedRulesSQLiRuleSet | SQLi_BODY | strict | BLOCK | 9 |
| AWSManagedRulesSQLiRuleSet | SQLi_QUERYARGUMENTS | __default__ | BLOCK | 1 |
| AWSManagedRulesSQLiRuleSet | SQLi_QUERYARGUMENTS | strict | BLOCK | 9 |
| custom:allowlist | AllowPublic | __default__ | ALLOW | 1 |
| custom:allowlist | AllowPublic | allowlist | ALLOW | 9 |
| custom:shop12 | OdooBodySizeOutsideRpc | shop12 | BLOCK | 14 |
| custom:shop12 | OdooRfiBodyOutsideRpc | shop12 | BLOCK | 11 |
| custom:shop12 | OdooXssBodyOutsideEditor | shop12 | BLOCK | 105 |
| custom:shop14 | OdooBodySizeOutsideRpc | shop14 | BLOCK | 24 |
| custom:shop14 | OdooRfiBodyOutsideRpc | shop14 | BLOCK | 15 |
| custom:shop14 | OdooXssBodyOutsideEditor | shop14 | BLOCK | 211 |
| custom:shop16 | OdooBodySizeOutsideRpc | shop16 | BLOCK | 26 |
| custom:shop16 | OdooRfiBodyOutsideRpc | shop16 | BLOCK | 15 |
| custom:shop16 | OdooXssBodyOutsideEditor | shop16 | BLOCK | 310 |
| custom:shop18 | OdooBodySizeOutsideRpc | shop18 | BLOCK | 36 |
| custom:shop18 | OdooRfiBodyOutsideRpc | shop18 | BLOCK | 15 |
| custom:shop18 | OdooXssBodyOutsideEditor | shop18 | BLOCK | 364 |
| custom:tuned | BlockLargeBodyOutsideRpc | __default__ | BLOCK | 2 |
| custom:tuned | BlockLargeBodyOutsideRpc | tuned | BLOCK | 15 |

## 3. Top 20 disagreements (action != aws_default_action)
| site_id | path | action | terminating_rule | aws_default_action | aws_default_rule | n |
|:-|:-|:-|:-|:-|:-|-:|
| tuned | /web/dataset/call_kw | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 14 |
| allowlist | /private/x | BLOCK | Default_Action | ALLOW |  | 9 |
| shadow | / | ALLOW | AWSManagedRulesCommonRuleSet/NoUserAgent_HEADER | BLOCK | AWSManagedRulesCommonRuleSet/NoUserAgent_HEADER | 9 |
| strict | / | BLOCK | AWSManagedRulesSQLiRuleSet/SQLi_QUERYARGUMENTS | ALLOW |  | 9 |
| strict | / | BLOCK | AWSManagedRulesAnonymousIpList/AnonymousIPList | ALLOW |  | 9 |
| strict | / | BLOCK | AWSManagedRulesSQLiRuleSet/SQLi_BODY | ALLOW |  | 9 |
| tuned | /files/a.log | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/RestrictedExtensions_URIPATH | 9 |
| tuned | /static-ok/x | ALLOW | Default_Action | BLOCK | AWSManagedRulesKnownBadInputsRuleSet/Log4JRCE_HEADER | 9 |
| shop12 | /web/dataset/call_kw/ir.attachment/create | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 6 |
| shop12 | /web/dataset/call_kw/res.partner/create | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 6 |
| shop12 | /web/dataset/call_kw/res.partner/message_post | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY | 6 |
| shop12 | /web/dataset/call_kw/res.partner/write | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 6 |
| shop14 | /web/dataset/call_kw/ir.attachment/create | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 6 |
| shop14 | /web/dataset/call_kw/res.partner/create | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 6 |
| shop14 | /web/dataset/call_kw/res.partner/message_post | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY | 6 |
| shop14 | /web/dataset/call_kw/res.partner/write | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 6 |
| shop16 | /web/dataset/call_kw/ir.attachment/create | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 6 |
| shop16 | /web/dataset/call_kw/res.partner/create | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 6 |
| shop16 | /web/dataset/call_kw/res.partner/message_post | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY | 6 |
| shop16 | /web/dataset/call_kw/res.partner/write | ALLOW | Default_Action | BLOCK | AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY | 6 |

## 4. Legit runs: BLOCK rows (must be 0)
| legit_blocks |
|-:|
| 0 |
| site_id | method | path | terminating_rule | run |
|:-|:-|:-|:-|:-|

## 5. Attack runs (nuclei, nikto): block rate per site
| site_id | tool | requests | blocked | block_pct |
|:-|:-|-:|-:|-:|
|  | nikto | 73 | 0 | 0 |
| demo | nikto | 4 | 4 | 100 |
| shop12 | nikto | 4914 | 4914 | 100 |
| shop12 | nuclei | 1973 | 395 | 20 |
| shop14 | nikto | 4914 | 4914 | 100 |
| shop14 | nuclei | 9967 | 2212 | 22.2 |
| shop16 | nikto | 4914 | 4914 | 100 |
| shop16 | nuclei | 15148 | 3489 | 23 |
| shop18 | nikto | 4914 | 4914 | 100 |
| shop18 | nuclei | 17374 | 4343 | 25 |
