# cef-text-to-csv-udf



## Getting started

This project is a UDF (scalar) for KSQLDB server.
The project contains source code and test code for a ksql UDF function.

## Use Case (Where this could be Used).
### - Cyber Intelligence & threat detection Usecases .
### - SIEM (Security information and event management) use cases:  
  
CyberIntelligence usecases gather data from many device within the orgarinzation.  Some of the devices send data in CEF format, (Common Event Format specification).  CEF format is in either JSON or Text format. Sending data in JSON format adds up to the size of message and network cost in cloud.  And to reduce the cost few organization send data in CSV-CEF format to downstream SIEM tools like Splunk.

Tools like Splunk , Streamset has CEF parser built in.  This source code is a UDF function which get data in Text format,  parses from CEF , customizes with addional details and sends data to an output topic in CSV format.

for CEF parsing this UDF utilizes the fluenda parCEFone library.

### CEF parser used:
https://github.com/fluenda/ParCEFone

### CEF Specification:

https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/#CEF/Chapter%201%20What%20is%20CEF.htm?TocPath=_____2

## What does the function do
Steps:
 -  Takes in a input Kafka record in String Format
 -  Splits into 2 String (Text)

        a) pre CEF
        b) CEF
 -  Pre CEF:

       Splits pre CEF string by "space" (\s) and creates the data for.

 -  CEF:

       invokes a CEF parser to create a CEF based record.

 -  Since output has to follow an order to match CSV header.

      Map the data of CEF parser to CSV output format, supports custom cs* Labels
 
 -  For a CSV since the order of output is important.

      output from the CEF parser are written as CSV string as provided in the List.


## quick commands
  - clone the repository
  - mvn clean
  - mvn test
  - mvn install
     Verify that the /target folder has a jar file with dependencies in it.
  - Deploy the jar file in all the nodes in KSQL-DB server.
  - Restart ksqlDB-server ( rolling restart)

   ### To validate if the function/udf is installed 
     ksql http://ksqldb-server:8088
    SHOW FUNCTIONS;
    DESCRIBE FUNCTION cefTextToCsv;

    CREATE STREAM cef_test_1 (
    VAL STRING
    ) WITH (
    KEY_FORMAT='NONE',
    VALUE_FORMAT = 'kafka',
    KAFKA_TOPIC = 'test_topic'
    );



    select * from cef_test_1;

    select cefTextToCsv(val,true) as cef_test_2 from cef_test_1 emit changes limit 10;

   - open kafkacat and publish a message with the following test data

## Sample CEF format input string
   2023-07-10T16:41:38.880480+00:00 kern.info fmsentlog02.amr.corp.intel.com CEF: 0|FORCEPOINT|Firewall|6.8.5|70018|Connection_Allowed|0|deviceExternalId=fm11d-zfg101a dvchost=10.18.110.232 dvc=10.18.110.232 src=10.45.8.149 dst=10.248.2.9 spt=43382 dpt=53 proto=17 deviceInboundInterface=130 act=Allow deviceFacility=Packet Filtering rt=Jul 10 2023 09:41:38 app=DNS (UDP) cs1Label=RuleID cs1=4443789.2


