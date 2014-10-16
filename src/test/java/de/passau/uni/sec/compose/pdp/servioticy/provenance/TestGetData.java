package de.passau.uni.sec.compose.pdp.servioticy.provenance;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.UUID;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.LocalPDP;
import de.passau.uni.sec.compose.pdp.servioticy.PDP;
import de.passau.uni.sec.compose.pdp.servioticy.PermissionCacheObject;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.reputation.Source;

public class TestGetData
{
	 private PDP pdp;

	 private String soid;
	 
	 private String streamid;
	 
	 @Before
	 public void setUp()
	 {
		 pdp = new LocalPDP();
		 pdp.setIdmUser("component");
		 pdp.setIdmPort(8080);
		 pdp.setIdmPassword("ZXJpZHMiLCJ");
		 pdp.setIdmHost("132.231.11.217");
		 soid = "123123";
		 streamid="stream";
		 
	 }


	 @Test
	 public  void RetrieveSourceFromSecurityMetadataSensorUpdate() throws PDPServioticyException
	 {
		
			try {
				System.out.println(generateSecurityMetadata(soid, streamid));
				ServioticyProvenance prov = new ServioticyProvenance();
				Source src = prov.getSourceFromSecurityMetaData(generateSecurityMetadata(soid, streamid));
				assertEquals(src.getSoid(), soid);
				assertEquals(src.getStreamid(), streamid);
				
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} 
	}
	 
	 @Test
	 public  void RetrieveSourceFromSecurityMetadataSensorUpdateWithoutProvenance() throws PDPServioticyException
	 {
		
			try {
				
				ServioticyProvenance prov = new ServioticyProvenance();
				Source src = prov.getSourceFromSecurityMetaData("");
				assertEquals(src.getSoid(), "");
				assertEquals(src.getStreamid(), "");
				src = prov.getSourceFromSecurityMetaData("{\"someThing\":12}");
				assertEquals(src.getSoid(), "");
				assertEquals(src.getStreamid(), "");
				
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} 
	}
	 
	 
	 private String generateSecurityMetadata(String soid, String streamid)
	 {
		String template = "{    \"policy\": [        [            {                \"flow\": {                    \"target\": \"user/testb\"                }            }        ],        [            {                \"flow\": {                    \"target\": \"user/testa\"                }            }        ]    ],    \"payment\": false,   "
				+ " \"provenance\": {        \"agent\": \"SO\",    "
				+ "    \"type\": \"sensor_update\",        "
				+ "\"entity\": \""+soid+"\",       "
				+ " \"activity\": [    {                \"op\": [],                \"var\": [                    \"a\",                    \"b\"                ]            }        ],      "
				+ " \"timestamp\": 1413445754839,      "
				+ " \"accessed\": [],      "
				+ "  \"onbehalf-of\": \"userid\",    "
				+ "    \"so-stream\": \""+streamid+"\","
				+ "        \"source\": [            { "
				+ "               \"entity\": \"SU-B-ID\",               "
								+ " \"source\": [ \"xx-b\" ]            },   "
								+ "{ \"entity\": \"Not_latest_source\",               \"source\": [                    \"xx-a\"                ]            }        ]    }}";
		return template;
	 }



	 
}
