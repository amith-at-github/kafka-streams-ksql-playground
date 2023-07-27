package com.intel.infosec.ci.ksql.udf;

//import com.github.jcustenborder.cef.CEFParserFactory;
//import com.github.jcustenborder.cef.Message;

import com.fluenda.parcefone.event.CEFHandlingException;
import com.fluenda.parcefone.event.CommonEvent;
import com.fluenda.parcefone.parser.CEFParser;
import io.confluent.ksql.function.udf.Udf;
import io.confluent.ksql.function.udf.UdfDescription;
import io.confluent.ksql.function.udf.UdfParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@UdfDescription(name = "cefTextToCsv", description = "Parse CEF in text format and generate CEF in CSV formatted String")
public class CefTextToCSVUdf {
    private static List<String> csvHeaderCefHeaderPrintList= Arrays.asList("cef_cefVersion","cef_name","cef_severity","cef_product","cef_signature","cef_vendor","cef_version");
    private static List<String> cefHeaderLookupList= Arrays.asList("version","name","severity","deviceProduct","deviceEventClassId","deviceVendor","deviceVersion");
    private static List<String> cefExtensionsLookupList= Arrays.asList("app","rt","dst","src","RuleID","dpt","deviceExternalId","deviceOutboundInterface","dvc","act","deviceInboundInterface","dvchost","spt","proto","deviceFacility","sourceTranslatedPort","sourceTranslatedAddress","destinationTranslatedPort","NatRuleId","destinationTranslatedAddress","msg","in","out","VulnerabilityReferences","smac","destinationServiceName","cat","suser");
    private static String csvHeaderCefExtensionPrefix="cef_extensions_";

    private static Logger log = LoggerFactory.getLogger(CefTextToCSVUdf.class);

    @Udf(description = "Parse CEF in text format and generate CEF in CSV formatted String")
    public String cefTextToCsv( @UdfParameter(value = "cefString")
                                final String  inputCEFText, @UdfParameter(value = "outputWithCSVHeader") final boolean outputWithCSVHeader)  {
        String s1 = inputCEFText.replace(" CEF: ","CEF:");
        String header = "";
        String cefStr = "";
        Pattern pattern = Pattern.compile("(.*)(CEF:.*)");
        Matcher matcher = pattern.matcher(s1);
        while (matcher.find()) {
            header = matcher.group(1);
            cefStr = matcher.group(2);
        }

        log.info("Starting UDF");
        CEFParser parser = new CEFParser();
        CommonEvent result = parser.parse(cefStr,false,true,Locale.ENGLISH);

        String outputCEFCsv = null;
        try {
            outputCEFCsv = printCSV(header,result,outputWithCSVHeader);
        } catch (CEFHandlingException e) {
            log.error ("ERROR during parsing"+ e);
            throw new RuntimeException(e);
        }
        return outputCEFCsv;
    }
    private String printCSV(String preHeader, CommonEvent commonEvt, boolean outputWithCSVHeader) throws CEFHandlingException {
        StringBuilder csvCefPreHeader = processCefPreHeader(preHeader, outputWithCSVHeader);
        StringBuilder csvCefHeader = processCefHeader(commonEvt,outputWithCSVHeader);
        Map<String,Object> extensionsMap = commonEvt.getExtension(true,true);
        StringBuilder csvCefExtensions = processCefExtensions(extensionsMap, outputWithCSVHeader);

        return csvCefPreHeader.append(csvCefHeader).append(csvCefExtensions).toString();
    }
    private static StringBuilder processCefPreHeader(String preHeader, boolean outputWithCSVHeader) {
        StringBuilder csvCefPreHeader = new StringBuilder();
        if(preHeader != null){
            String[] parts = preHeader.split("\\s");
            if(outputWithCSVHeader){
                csvCefPreHeader.append("ts=").append(parts[0]).append(",facility_priority=").append(parts[1])
                        .append(",rptr_host=").append(parts[2]) ;
            }else {
                csvCefPreHeader.append(parts[0]).append(",").append(parts[1]).append(",").append(parts[2]);
            }
        }
        return csvCefPreHeader;
    }
    private StringBuilder processCefHeader(CommonEvent commonEvt, boolean outputWithCSVHeader) throws CEFHandlingException {
        StringBuilder csvCefHeader = new StringBuilder();
        for (int i=0;i<cefHeaderLookupList.size(); i++){
            if(outputWithCSVHeader) {
                csvCefHeader.append(",").append(csvHeaderCefHeaderPrintList.get(i)).append("=").append(commonEvt.getHeader().get(cefHeaderLookupList.get(i)));
            } else {
                csvCefHeader.append(",").append(commonEvt.getHeader().get(cefHeaderLookupList.get(i)));
            }
        }
        return csvCefHeader;
    }
    private StringBuilder processCefExtensions(Map<String, Object> extensionsMap, boolean outputWithCSVHeader) {
        StringBuilder csvCefExtensions = new StringBuilder();
        for (String item: cefExtensionsLookupList){
            if(outputWithCSVHeader) {
                csvCefExtensions.append( ",").append(csvHeaderCefExtensionPrefix).append(item).append(":").append(getExtensionValue(extensionsMap, item));
            }else {
                csvCefExtensions.append(",").append(getExtensionValue(extensionsMap, item));
            }
        }
        return csvCefExtensions;
    }
    private static String getExtensionValue(Map<String, Object> extensionsMap, String item) {
        String extensionValue = "";
        if(extensionsMap.containsKey(item)) {
            if(extensionsMap.get(item) instanceof Date){
                extensionValue = new SimpleDateFormat("MMM dd YYYY HH:mm:ss").format(extensionsMap.get(item));
            } else if (extensionsMap.get(item) instanceof InetAddress){
                extensionValue = ((InetAddress) extensionsMap.get(item)).getHostAddress();
            } else {
                extensionValue = extensionsMap.get(item).toString();
                if(!extensionValue.isEmpty() && extensionValue.contains(","))
                    extensionValue = "\""+extensionValue.replaceAll(",",";")+"\"";
            }
        }else{
            if (item.equals("RuleID")){
                extensionValue = extensionsMap.getOrDefault("cs1","").toString();
            } else  if (item.equals("NatRuleId")){
                extensionValue = extensionsMap.getOrDefault("cs2","").toString();
            } else if (item.equals("VulnerabilityReferences")){
                extensionValue = extensionsMap.getOrDefault("cs3","").toString();
                if (!extensionValue.isEmpty() && extensionValue.contains(",")){
                    extensionValue = "\""+extensionValue.replaceAll(",",";")+"\"";
                }
            }
        }
        return extensionValue;
    }
}