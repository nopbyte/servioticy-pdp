package de.passau.uni.sec.compose.pdp.servioticy;

import static org.junit.Assert.*;
import org.junit.rules.ExpectedException.*;

import java.io.IOException;
import java.util.UUID;
import java.util.List;
import java.util.LinkedList;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.provenance.ServioticyProvenance;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

import com.jayway.jsonpath.Criteria;
import com.jayway.jsonpath.Filter;
import com.jayway.jsonpath.JsonPath;

import java.util.Map;
import java.util.HashMap;

public class TestInitialProv 
{
	 private PDP pdp; 
	
	 @Before
	 public void setUp()
	 {
		 pdp = new LocalPDP();
	 }
	
	 @Test
	 public  void initialProvenanceOK() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadata(token);
				// Get initial provenance
				ret = pdp.SendDataToServiceObjectProv(token, so_data, null, null, "Stream1");
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check initial provenance (if it is a valide JSON doc and if it has the right provenance onbehalf entry)
				JsonNode retNode = ret.getSecurityMetaData();
				String policy = retNode.findValue("policy").toString();
				String onbehalf = retNode.findValue("onbehalf").asText();
				assertEquals("[{\"flow\":{\"forall\":\"entities\",\"target\":\"entities\"}},{\"flow\":{\"forall\":\"entities\",\"source\":\"entities\"}}]", policy);
				assertEquals("owner_identifier123123", onbehalf);




				//ret = pdp.checkAuthorization(token, so_data, null, null, PDP.operationID.SendDataToServiceObject);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
  
			
	 }



	 @Test
	 public  void basicDispatchPublisher()
	 {
		  	PermissionCacheObject ret = new PermissionCacheObject();
			ret.setChannel("Channel1");
			ret.setUserId("12345user");
			String Channel = "";
			String User = "";
		
			if(ret != null && ret.getCache() instanceof Map)
			{
				Map temp = (Map<String, Object>)ret.getCache();
				if(temp.containsKey("Channel"))
					Channel = (String)temp.get("Channel");
			}


			if(ret != null && ret.getCache() instanceof Map)
			{
				Map temp = (Map<String, Object>)ret.getCache();
				if(temp.containsKey("UserId"))
					User = (String)temp.get("UserId");
			}
			System.out.println("Ret: " + ret.getCache());
			assertEquals("12345user", User);
			assertEquals("Channel1", Channel);
		
	 }
	 /**
	  * 
	  * @param token
	  * @return A subset of 
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSoMetadata(String token) throws JsonProcessingException, IOException {
		     String string = "{\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"owner_identifier123123\", \"policy\" :[{\"flow\" : { \"forall\" : \"entities\", \"target\" : \"entities\" }},{\"flow\" : { \"forall\" : \"entities\", \"source\" : \"entities\" }}]}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}


	 @Test(expected = PDPServioticyException.class)
	 public  void initialProvenanceFailerNull() throws PDPServioticyException
	 {
			String token=UUID.randomUUID().toString();
			pdp.SendDataToServiceObjectProv(token, null, null, null, "Stream");
			assertEquals(1, 2);
	 }

	 @Test(expected = PDPServioticyException.class)
	 public  void initialProvenanceFailerJSON() throws JsonProcessingException, IOException, PDPServioticyException 
	 {
			String token=UUID.randomUUID().toString();
		    	ObjectMapper mapper = new ObjectMapper();
			JsonNode so_data = mapper.readTree("{\"bla\" : \"blub\"}");
			PermissionCacheObject ret = pdp.SendDataToServiceObjectProv(token, so_data, null, null, "Stream1");
	
	 }

}
