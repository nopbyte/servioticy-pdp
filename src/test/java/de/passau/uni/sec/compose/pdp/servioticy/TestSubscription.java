package de.passau.uni.sec.compose.pdp.servioticy;

import static org.junit.Assert.*;
import org.junit.rules.ExpectedException.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.List;
import java.util.LinkedList;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.junit.Before;
import org.junit.Test;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.provenance.ServioticyProvenance;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.*;

import com.jayway.jsonpath.Criteria;
import com.jayway.jsonpath.Filter;
import com.jayway.jsonpath.JsonPath;

public class TestSubscription 
{
	 private PDP pdp; 
	
	 @Before
	 public void setUp()
	 {
		 pdp = new LocalPDP();
		 pdp.setIdmUser("idmUser");
		 pdp.setIdmPort(80);
		 pdp.setIdmPassword("pw");
		 pdp.setIdmHost("idm4.147.83.30.133.xip.io");
	 }
	
	 @Test
	 public  void getSubscriptionInfoCacheTrue() throws PDPServioticyException
	 {
		  	PermissionCacheObject cache = new PermissionCacheObject();
			PermissionCacheObject ret;
			String token = "dummyToken";
			String subInfo = "{\"subscriptions\":[{\"id\":\"0f3a8f9baf87401a8e0434de8ef55d64\",\"userId\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"createdAt\":1437491584197,\"updatedAt\":1437491584197,\"callback\":\"pubsub\",\"source\":\"1437484068100d8b2198a0831446fa9d761def8483fa2\",\"destination\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"stream\":\"weather\"},{\"id\":\"39b29d5a8ce2492ebcd516b4671b31b9\",\"userId\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"createdAt\":1437491438905,\"updatedAt\":1437491438905,\"callback\":\"pubsub\",\"source\":\"1437484068100d8b2198a0831446fa9d761def8483fa2\",\"destination\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"stream\":\"weather\"},{\"id\":\"86ffd6177642434d8683654c7329611e\",\"userId\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"createdAt\":1437485348274,\"updatedAt\":1437485348274,\"callback\":\"pubsub\",\"source\":\"1437484068100d8b2198a0831446fa9d761def8483fa2\",\"destination\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"stream\":\"weather\"}]}";
			cache.setSubscriptionInfo(subInfo);
			cache.setUserId("ade0456b-af8b-4348-b640-adfb51e9c02b");
			try {
				ret = pdp.checkAuthorization(token, null, null, cache, PDP.operationID.GetThisSubscriptionInfoForStream);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(true, pdpResult);
			} catch (Exception e) {
				fail();
			}
			
	 }


	 @Test
	 public  void getSubscriptionInfoCacheFalse() throws PDPServioticyException
	 {
		  	PermissionCacheObject cache = new PermissionCacheObject();
			PermissionCacheObject ret;
			String token = "dummyToken";
			String subInfo = "{\"subscriptions\":[{\"id\":\"0f3a8f9baf87401a8e0434de8ef55d64\",\"userId\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"createdAt\":1437491584197,\"updatedAt\":1437491584197,\"callback\":\"pubsub\",\"source\":\"1437484068100d8b2198a0831446fa9d761def8483fa2\",\"destination\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"stream\":\"weather\"},{\"id\":\"39b29d5a8ce2492ebcd516b4671b31b9\",\"userId\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"createdAt\":1437491438905,\"updatedAt\":1437491438905,\"callback\":\"pubsub\",\"source\":\"1437484068100d8b2198a0831446fa9d761def8483fa2\",\"destination\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"stream\":\"weather\"},{\"id\":\"86ffd6177642434d8683654c7329611e\",\"userId\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"createdAt\":1437485348274,\"updatedAt\":1437485348274,\"callback\":\"pubsub\",\"source\":\"1437484068100d8b2198a0831446fa9d761def8483fa2\",\"destination\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"stream\":\"weather\"}]}";
			cache.setSubscriptionInfo(subInfo);
			cache.setUserId("ade0456b-af8b-4348-b640-adfb51e9c02XX");
			try {
				ret = pdp.checkAuthorization(token, null, null, cache, PDP.operationID.GetThisSubscriptionInfoForStream);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(false, pdpResult);
			} catch (Exception e) {
				fail();
			}	
	 }



	 
	 public  void getSubscriptionInfoIdmTrue() throws PDPServioticyException
	 {
			// Get Accesstoken from IDM
			IDMCommunicator com = new IDMCommunicator("component", "ZXJpZHMiLCJ", "idm4.147.83.30.133.xip.io", 80);
			try {

				CloseableHttpResponse responsePost = com.sendPostToIDM("/auth/user/","{\"username\" : \"servioticyTest\",\"password\" : \"pass\"}");
				ObjectMapper mapper = new ObjectMapper();
				String retIDM = EntityUtils.toString(responsePost.getEntity());
				System.out.println("Response from IDM: " + retIDM);
				JsonNode response = mapper.readTree(retIDM);
				JsonNode accesToken = response.findValue("accessToken");

			  	PermissionCacheObject cache = new PermissionCacheObject();
				PermissionCacheObject ret;
				String subInfo = "{\"subscriptions\":[{\"id\":\"0f3a8f9baf87401a8e0434de8ef55d64\",\"userId\":\"ceb91103-2424-4001-8f1c-23cbaa451a2d\",\"createdAt\":1437491584197,\"updatedAt\":1437491584197,\"callback\":\"pubsub\",\"source\":\"1437484068100d8b2198a0831446fa9d761def8483fa2\",\"destination\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"stream\":\"weather\"}]}";
				cache.setSubscriptionInfo(subInfo);
				ret = pdp.checkAuthorization(accesToken.asText(), null, null, cache, PDP.operationID.GetThisSubscriptionInfoForStream);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(true, pdpResult);
				assertEquals("ceb91103-2424-4001-8f1c-23cbaa451a2d", ret.getUserId());
				com.clear();
			} catch (Exception e) {
				System.out.println(e);
				com.clear();
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"" + userid + "\", \"policy\" :[{\"object\":{\"type\":\"so\",\"id\":\"123\"},\"flows\":[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}]}}"; 
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\",\"owner_id\":\""+ userid + "\", \"policy\" :[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}}";
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"owner_identifier123123\", \"policy\" :[{\"object\":{\"type\":\"so\",\"id\":\"123\"},\"flows\":[{\"source\":{\"type\":\"any\"}},{\"target\":{\"type\":\"any\"}}]}]}}";
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\",\"owner_id\":\"owner_identifier123123\", \"policy\" :[{\"source\":{\"type\":\"any\"}},{\"target\":{\"type\":\"any\"}}]}}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}

//...................................................
	 /**
	  * 
	  * @param token
	  * @return SO with public policy 
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSoMetadataPrivate2(String token, String userid) throws JsonProcessingException, IOException {
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"" + userid + "\", \"policy\" :[{\"object\":{\"type\":\"so\",\"id\":\"123\"},\"flows\":[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}]}}"; 
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
	 private JsonNode buildJsonSuMetadataPrivate2(String userid) throws JsonProcessingException, IOException {
		userid += "7";
	     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"owner_id\":\"" + userid + "\", \"policy\" :[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}}"; 
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}



}
