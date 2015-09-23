package de.passau.uni.sec.compose.pdp.servioticy.idm;

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

public class TestSOActionsPrivatePublicIDM
{
	 private PDP pdp;

	 @Before
	 public void setUp()
	 {
		 pdp = new LocalPDP();
		 pdp.setIdmUser("component");
		 pdp.setIdmPort(8080);
		 pdp.setIdmPassword("dummyTest");
		 pdp.setIdmHost("132.231.11.217");
	 }


	 //@Test
	 public  void RetrieveServiceObjectDescriptionCachePublicIDM() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPublic(token);
				// Get token
				 IDMCommunicator com = new IDMCommunicator("component", "dummyTest", "132.231.11.217", 8080);
				CloseableHttpResponse responsePost = com.sendPostToIDM("/auth/user/","{\"username\" : \"test2\",\"password\" : \"pass\"}");
				ObjectMapper mapper = new ObjectMapper();
			    JsonNode response = mapper.readTree(EntityUtils.toString(responsePost.getEntity()));
			    com.clear();

				JsonNode accesToken = response.findValue("accessToken");
				// Get initial provenance
				ret = pdp.checkAuthorization(accesToken.asText(), so_data, null, null, PDP.operationID.RetrieveServiceObjectDescription);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				System.out.println("IDM" + ret.getUserId());
				boolean pdpResult = ret.isPermission();
				assertEquals(ret.getUserId(), "92f83ea4-2835-4dce-a34a-5711d948c610");
				assertEquals(true, pdpResult);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
	 }

	 //@Test
	 public  void RetrieveServiceObjectDescriptionCachePrivateOKIDM() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				
				/// Get token
				 IDMCommunicator com = new IDMCommunicator("component", "dummyTest", "132.231.11.217", 8080);
				CloseableHttpResponse responsePost = com.sendPostToIDM("/auth/user/","{\"username\" : \"test2\",\"password\" : \"pass\"}");
				ObjectMapper mapper = new ObjectMapper();
			    JsonNode response;
				response = mapper.readTree(EntityUtils.toString(responsePost.getEntity()));
			    com.clear();

				JsonNode accesToken = response.findValue("accessToken");
				// Get initial provenance
				ret = pdp.checkAuthorization(accesToken.asText(), null, null, null, PDP.operationID.GetUserInfo);
				JsonNode so_data = buildJsonSuMetadataPrivate(ret.getUserId());
				// Get initial provenance
				ret = pdp.checkAuthorization(accesToken.asText(), so_data, null, null, PDP.operationID.RetrieveServiceObjectDescription);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				System.out.println("IDM" + ret.getUserId());
				boolean pdpResult = ret.isPermission();
				assertEquals(ret.getUserId(), "92f83ea4-2835-4dce-a34a-5711d948c610");
				assertEquals(true, pdpResult);
				
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
	 }

	 
	 //@Test
	 public  void RetrieveServiceObjectDescriptionCachePrivateFalseIDM() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				
				/// Get token
				 IDMCommunicator com = new IDMCommunicator("component", "dummyTest", "132.231.11.217", 8080);
				CloseableHttpResponse responsePost = com.sendPostToIDM("/auth/user/","{\"username\" : \"test2\",\"password\" : \"pass\"}");
				ObjectMapper mapper = new ObjectMapper();
			    JsonNode response;
				response = mapper.readTree(EntityUtils.toString(responsePost.getEntity()));
			    com.clear();

				JsonNode accesToken = response.findValue("accessToken");
				// Get initial provenance
				ret = pdp.checkAuthorization(accesToken.asText(), null, null, null, PDP.operationID.GetUserInfo);
				JsonNode so_data = buildJsonSuMetadataPrivate(ret.getUserId()+"garbage...");
				// Get initial provenance
				ret = pdp.checkAuthorization(accesToken.asText(), so_data, null, null, PDP.operationID.RetrieveServiceObjectDescription);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				System.out.println("IDM" + ret.getUserId());
				boolean pdpResult = ret.isPermission();
				assertEquals(ret.getUserId(), "92f83ea4-2835-4dce-a34a-5711d948c610");
				assertEquals(false, pdpResult);
				
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
	 }
	 
	 /**
	  *
	  * @param token
	  * @return SO with public policy
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSoMetadataPrivate(String token, String userid) throws JsonProcessingException, IOException {
		String policy = "[{\"object\":{\"type\":\"so\",\"id\":\"123\"},\"flows\":[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}]";
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"" + userid + "\", \"policy\" :[{\"flow\" : { \"target\" : \"userid/" + userid + "\" }},{\"flow\" : { \"source\" : \"userid/" + userid + "\" }}]}}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}


	 /**
	  *
	  * @return Su
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSuMetadataPrivate(String userid) throws JsonProcessingException, IOException {
		String policy = "[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]";
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\",\"owner_id\":\""+ userid + "\", \"policy\" :" + policy + "}}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}


	 /**
	  *
	  * @param token
	  * @return SO with public policy
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSoMetadataPublic(String token) throws JsonProcessingException, IOException {
		String policy = "[{\"object\":{\"type\":\"so\",\"id\":\"123\"},\"flows\":[{\"source\":{\"type\":\"any\"}},{\"target\":{\"type\":\"any\"}}]}]";
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"owner_identifier123123\", \"policy\" :" + policy + "}}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}


	 /**
	  *
	  * @return Su
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSuMetadataPublic() throws JsonProcessingException, IOException {
		String policy = "[{\"source\":{\"type\":\"any\"}},{\"target\":{\"type\":\"any\"}}]";
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\",\"owner_id\":\"owner_identifier123123\", \"policy\" :"+ policy + "}}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}

}
