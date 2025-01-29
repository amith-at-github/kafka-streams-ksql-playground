package com.infosec.ci.ksql.udf;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertEquals;

public class CefTextToCSVUdfTest {
    private static Logger log = LoggerFactory.getLogger(CefTextToCSVUdfTest.class);
    String testStringCs1 = "2023-07-10T16:41:38.880480+00:00 kern.info sample02.corp.com CEF: 0|FORCEPOINT|Firewall|6.8.5|70018|Connection_Allowed|0|deviceExternalId=fm11d-zfg101a dvchost=10.18.110.232 dvc=10.18.110.232 src=110.45.8.149 dst=10.248.2.9 spt=43382 dpt=53 proto=17 deviceInboundInterface=130,130 act=Allow deviceFacility=Packet Filtering rt=Jul 10 2023 09:41:38 app=DNS (UDP) cs1Label=RuleID cs1=4443789.2";
    String testStringCs2 = "2023-07-10T16:41:38.880480+00:00 kern.info sample02.corp.com CEF: 0|FORCEPOINT|Firewall|6.8.5|70018|Connection_Allowed|0|deviceExternalId=fm11d-zfg101a dvchost=10.18.110.232 dvc=10.18.110.232 src=110.45.8.149 dst=10.248.2.9 spt=43382 dpt=53 proto=17 deviceInboundInterface=130,130 act=Allow deviceFacility=Packet Filtering rt=Jul 10 2023 09:41:38 app=DNS (UDP) cs1Label=RuleID cs1=4443789.2 cs2Label=NatRuleId cs2=4443789.2";
    String testStringCs3 = "2023-07-10T16:41:38.880480+00:00 kern.info sample02.corp.com CEF: 0|FORCEPOINT|Firewall|6.8.5|70018|Connection_Allowed|0|deviceExternalId=fm11d-zfg101a dvchost=10.18.110.232 dvc=10.18.110.232 src=110.45.8.149 dst=10.248.2.9 spt=43382 dpt=53 proto=17 deviceInboundInterface=130,130 act=Allow deviceFacility=Packet Filtering rt=Jul 10 2023 09:41:38 app=DNS (UDP) cs1Label=RuleID cs1=4443789.2 cs3Label=VulnerabilityReferences cs3=BID-67153,CVE-2014-3000,OSVDB-106442";
    String testStringCs4 = "2023-07-10T16:41:38.880480+00:00 kern.info sample02.corp.com CEF: 0|FORCEPOINT|Firewall|6.8.5|70018|Connection_Allowed|0|deviceExternalId=fm11d-zfg101a dvchost=10.18.110.232 dvc=10.18.110.232 src=110.45.8.149 dst=10.248.2.9 spt=43382 dpt=53 proto=17 deviceInboundInterface=130,130 act=Allow deviceFacility=Packet Filtering rt=Jul 10 2023 09:41:38 app=DNS (UDP) cs1Label=RuleID cs1=4443789.2 cs3Label=VulnerabilityReferences cs3=42";

    String outputStringWithHeaderCs1="ts=2023-07-10T16:41:38.880480+00:00,facility_priority=kern.info,rptr_host=sample02.corp.com,cef_cefVersion=0,cef_name=Connection_Allowed,cef_severity=0,cef_product=Firewall,cef_signature=70018,cef_vendor=FORCEPOINT,cef_version=6.8.5,cef_extensions_app:DNS (UDP),cef_extensions_rt:Jul 10 2023 09:41:38,cef_extensions_dst:10.248.2.9,cef_extensions_src:110.45.8.149,cef_extensions_RuleID:4443789.2,cef_extensions_dpt:53,cef_extensions_deviceExternalId:fm11d-zfg101a,cef_extensions_deviceOutboundInterface:,cef_extensions_dvc:10.18.110.232,cef_extensions_act:Allow,cef_extensions_deviceInboundInterface:\"130;130\",cef_extensions_dvchost:10.18.110.232,cef_extensions_spt:43382,cef_extensions_proto:17,cef_extensions_deviceFacility:Packet Filtering,cef_extensions_sourceTranslatedPort:,cef_extensions_sourceTranslatedAddress:,cef_extensions_destinationTranslatedPort:,cef_extensions_NatRuleId:,cef_extensions_destinationTranslatedAddress:,cef_extensions_msg:,cef_extensions_in:,cef_extensions_out:,cef_extensions_VulnerabilityReferences:,cef_extensions_smac:,cef_extensions_destinationServiceName:,cef_extensions_cat:,cef_extensions_suser:";
    String outputStringWithoutHeaderCs1="2023-07-10T16:41:38.880480+00:00,kern.info,sample02.corp.com,0,Connection_Allowed,0,Firewall,70018,FORCEPOINT,6.8.5,DNS (UDP),Jul 10 2023 09:41:38,10.248.2.9,110.45.8.149,4443789.2,53,fm11d-zfg101a,,10.18.110.232,Allow,\"130;130\",10.18.110.232,43382,17,Packet Filtering,,,,,,,,,,,,,";

    String outputStringWithHeaderCs2="ts=2023-07-10T16:41:38.880480+00:00,facility_priority=kern.info,rptr_host=sample02.corp.com,cef_cefVersion=0,cef_name=Connection_Allowed,cef_severity=0,cef_product=Firewall,cef_signature=70018,cef_vendor=FORCEPOINT,cef_version=6.8.5,cef_extensions_app:DNS (UDP),cef_extensions_rt:Jul 10 2023 09:41:38,cef_extensions_dst:10.248.2.9,cef_extensions_src:110.45.8.149,cef_extensions_RuleID:4443789.2,cef_extensions_dpt:53,cef_extensions_deviceExternalId:fm11d-zfg101a,cef_extensions_deviceOutboundInterface:,cef_extensions_dvc:10.18.110.232,cef_extensions_act:Allow,cef_extensions_deviceInboundInterface:\"130;130\",cef_extensions_dvchost:10.18.110.232,cef_extensions_spt:43382,cef_extensions_proto:17,cef_extensions_deviceFacility:Packet Filtering,cef_extensions_sourceTranslatedPort:,cef_extensions_sourceTranslatedAddress:,cef_extensions_destinationTranslatedPort:,cef_extensions_NatRuleId:4443789.2,cef_extensions_destinationTranslatedAddress:,cef_extensions_msg:,cef_extensions_in:,cef_extensions_out:,cef_extensions_VulnerabilityReferences:,cef_extensions_smac:,cef_extensions_destinationServiceName:,cef_extensions_cat:,cef_extensions_suser:";
    String outputStringWithHeaderCs3="ts=2023-07-10T16:41:38.880480+00:00,facility_priority=kern.info,rptr_host=sample02.corp.com,cef_cefVersion=0,cef_name=Connection_Allowed,cef_severity=0,cef_product=Firewall,cef_signature=70018,cef_vendor=FORCEPOINT,cef_version=6.8.5,cef_extensions_app:DNS (UDP),cef_extensions_rt:Jul 10 2023 09:41:38,cef_extensions_dst:10.248.2.9,cef_extensions_src:110.45.8.149,cef_extensions_RuleID:4443789.2,cef_extensions_dpt:53,cef_extensions_deviceExternalId:fm11d-zfg101a,cef_extensions_deviceOutboundInterface:,cef_extensions_dvc:10.18.110.232,cef_extensions_act:Allow,cef_extensions_deviceInboundInterface:\"130;130\",cef_extensions_dvchost:10.18.110.232,cef_extensions_spt:43382,cef_extensions_proto:17,cef_extensions_deviceFacility:Packet Filtering,cef_extensions_sourceTranslatedPort:,cef_extensions_sourceTranslatedAddress:,cef_extensions_destinationTranslatedPort:,cef_extensions_NatRuleId:,cef_extensions_destinationTranslatedAddress:,cef_extensions_msg:,cef_extensions_in:,cef_extensions_out:,cef_extensions_VulnerabilityReferences:\"BID-67153;CVE-2014-3000;OSVDB-106442\",cef_extensions_smac:,cef_extensions_destinationServiceName:,cef_extensions_cat:,cef_extensions_suser:";

    @Test
    public void testCefTextToCsvWithHeader() {
        String s1 = new CefTextToCSVUdf().cefTextToCsv(testStringCs1,true);
        assertEquals(outputStringWithHeaderCs1, s1);
        log.info("output with Header log --> "+ s1);
    }

    @Test
    public void testCefTextToCsvWithoutHeader() {
        String s2= new CefTextToCSVUdf().cefTextToCsv(testStringCs1,false);
        assertEquals(outputStringWithoutHeaderCs1, s2);
        log.info("output without Header --> "+ s2);
    }

    @Test
    public void testCefTextToCsvWithHeaderCS2() {
        String s2= new CefTextToCSVUdf().cefTextToCsv(testStringCs2,true);
        assertEquals(outputStringWithHeaderCs2, s2);
        log.info("output with Header --> "+ s2);
    }

    @Test
    public void testCefTextToCsvWithHeaderCS3() {
        String s2= new CefTextToCSVUdf().cefTextToCsv(testStringCs3,true);
        assertEquals(outputStringWithHeaderCs3, s2);
        log.info("output with Header --> "+ s2);
    }

}