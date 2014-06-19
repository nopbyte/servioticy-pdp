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
				pdp.checkAuthorization(token, so_data, null, null, PDP.operationID.SendDataToServiceObject);
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
				pdp.checkAuthorization(UUID.randomUUID().toString(), so_data, null, null, PDP.operationID.SendDataToServiceObject);
		        fail();
		    }
		    catch (PDPServioticyException e) 
			{
				assertTrue(true);
			} catch (JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				fail();
			}
			
	 }
}
