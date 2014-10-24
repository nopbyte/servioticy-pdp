package de.passau.uni.sec.compose.pdp.servioticy;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

public class PostDataToServiceObjectFromTheOutside 
{
	 private PDP pdp; 
	
	 @Before
	 public void setUp()
	 {
		 pdp = new LocalPDP();
	 }
	
	 @Test
	 public  void postDataToSOCallCorrect() throws PDPServioticyException
	 {
		  
			try {
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadata(token);
				pdp.SendDataToServiceObjectProv(token, so_data, null, null, "Stream1");
			} catch (JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				fail();
			}
	        
		  
			
	 }
	 /**
	  * 
	  * @param token
	  * @return A subset of 
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSoMetadata(String token) throws JsonProcessingException, IOException {
		     String string = "{\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"owner_identifier123123\"}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}

	@Test
	 public  void postDataToSOCallIncorrect() throws PDPServioticyException
	 {
			
		    try{
		    	String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadata("wrong token");
				pdp.SendDataToServiceObjectProv(UUID.randomUUID().toString(), so_data, null, null, "Stream2");
		        fail();
		    }
		    catch (PDPServioticyException e) 
			{
		    	System.out.println("User message: "+ e.getMessage()+",  log message: "+e.getLogInfo()+ ",HTTP error code: "+e.getStatus());
				assertTrue(true);
			} catch (JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				fail();
			}
			
	 }
	
	
	 /**
	  * 
	  * @param token
	  * @return A subset of 
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSoMetadataWithPolicy(String token) throws JsonProcessingException, IOException {
		     String string = "{\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"owner_identifier123123\", \"policy\" : [{\"flow\" : { \"forall\" : \"entities\", \"target\" : \"entities\" }},{\"flow\" : { \"forall\" : \"entities\", \"source\" : \"entities\" }}]}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}
	@Test
	 public  void postDataToSOcheckReturnedData() throws PDPServioticyException
	 {
		PermissionCacheObject ret = null;
		JsonNode so_data = null;
		try {
			String token=UUID.randomUUID().toString();
			so_data = buildJsonSoMetadataWithPolicy(token);
			ret = pdp.SendDataToServiceObjectProv(token, so_data, null, null, "Stream1");
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			fail();
		}
		JsonNode retNode = (JsonNode) ret.getSecurityMetaData();
		assertEquals(so_data.findValue("policy"), retNode.findValue("policy"));	
	 }
}



