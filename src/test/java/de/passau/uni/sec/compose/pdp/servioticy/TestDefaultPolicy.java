package de.passau.uni.sec.compose.pdp.servioticy;

import static org.junit.Assert.*;
import org.junit.rules.ExpectedException.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
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

public class TestDefaultPolicy 
{
	 private PDP pdp; 
	
	 @Before
	 public void setUp()
	 {
		 pdp = new LocalPDP();
		 pdp.setIdmUser("idmUser");
		 pdp.setIdmPort(8080);
		 pdp.setIdmPassword("pw");
		 pdp.setIdmHost("host");
	 }
	
	 @Test
	 public  void wrongUIDinPolicy() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPrivate2(token, "123");
				JsonNode su_data = buildJsonSuMetadataPrivate2("123");
				// Get initial provenance
				System.out.println("SO: " + so_data);
				System.out.println("SU: " + su_data);
				ret = pdp.checkAuthorization(token, so_data, su_data, null, PDP.operationID.DispatchData);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(false, pdpResult);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
  
			
	 }







	 @Test
	 public  void defaultpolicyPublic() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
		  	ret = new PermissionCacheObject();
		  	ret.setStream("weather");
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPublic(token);
				JsonNode su_data = buildJsonSuMetadataPublic();
				// Get initial provenance
				ret = pdp.checkAuthorization(token, so_data, su_data, ret, PDP.operationID.DispatchData);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(true, pdpResult);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
  
			
	 }

	 @Test
	 public  void defaultpolicyPublicNoStream() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPublic(token);
				JsonNode su_data = buildJsonSuMetadataPublic();
				// Get initial provenance
				ret = pdp.checkAuthorization(token, so_data, su_data, null, PDP.operationID.DispatchData);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(true, pdpResult);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
  
			
	 }


	 @Test
	 public  void defaultpolicyPrivateOk() throws PDPServioticyException
	 {
		 	System.out.println("defaultpolicyPrivateOk");
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPrivate(token, "123");
				JsonNode su_data = buildJsonSuMetadataPrivate("123");
				// Get initial provenance
				ret = pdp.checkAuthorization(token, so_data, su_data, null, PDP.operationID.DispatchData);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				System.out.println("defaultpolicyPrivateOk--> End");
				assertEquals(true, pdpResult);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
  
			
	 }


	 @Test
	 public  void defaultpolicyPrivateFalse() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPrivate(token, "1234");
				JsonNode su_data = buildJsonSuMetadataPrivate("5678");
				// Get initial provenance
				ret = pdp.checkAuthorization(token, so_data, su_data, null, PDP.operationID.DispatchData);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(false, pdpResult);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
  
			
	 }

	 @Test
	 public  void RetrieveServiceObjectDataCachePublic() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			PermissionCacheObject inputCache = new PermissionCacheObject();
			inputCache.setUserId("123");
			try {
				// Generate input
				inputCache.setUserInfo(getUserInfo());
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPublic(token);
				JsonNode su_data = buildJsonSuMetadataPublic();
				// Get initial provenance
				ret = pdp.checkAuthorization(token, so_data, su_data, inputCache, PDP.operationID.RetrieveServiceObjectData);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(true, pdpResult);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
  
			
	 }




	@Test
	 public  void RetrieveServiceObjectDataCachePrivateOK() throws PDPServioticyException
	 {
			System.out.println("RetrieveServiceObjectDataCachePrivateOK");
		  	PermissionCacheObject ret;
			PermissionCacheObject inputCache = new PermissionCacheObject();
			inputCache.setUserId("123");
			try {
				inputCache.setUserInfo(getUserInfo("123"));
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPrivate(token, "123");
				JsonNode su_data = buildJsonSuMetadataPrivate("123");
				// Get initial provenance
				ret = pdp.checkAuthorization(token, so_data, su_data, inputCache, PDP.operationID.RetrieveServiceObjectData);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(true, pdpResult);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
  
			
	 }

	 @Test
	 public  void RetrieveServiceObjectDataCachePrivateFalse() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			PermissionCacheObject inputCache = new PermissionCacheObject();
			inputCache.setUserId("123");
			try {
				inputCache.setUserInfo(getUserInfo());
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPrivate(token, "123");
				JsonNode su_data = buildJsonSuMetadataPrivate("123");	
				// Get initial provenance
				ret = pdp.checkAuthorization(token, so_data, su_data, inputCache, PDP.operationID.RetrieveServiceObjectData);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(false, pdpResult);
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
  
			
	 }

	 
	 @Test
	 public  void dispatchReturnMetaData() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPublic(token);
				JsonNode su_data = buildJsonSuMetadataPublic();
				// Get initial provenance
				ret = pdp.checkAuthorization(token, so_data, su_data, null, PDP.operationID.DispatchData);
				// Check the result of the policy evaluation
				boolean pdpResult = ret.isPermission();
				assertEquals(true, pdpResult);
				assertEquals(so_data.findValue("policy"), ret.getSecurityMetaData().findValue("policy"));
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"" + userid + "\", \"policy\" :[{\"object\":{\"type\":\"so\",\"id\":\"13412341234123412341324\"},\"flows\":[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}]}}"; 
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
		     String string = "{\"security\" : {\"id\":\""+ userid + "\",\"owner_id\":\""+ userid + "\", \"policy\" :[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}}";
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"owner_identifier123123\", \"policy\" :[{\"object\":{\"type\":\"so\",\"id\":\"13412341234123412341324\"},\"flows\":[{\"source\":{\"type\":\"any\"}},{\"target\":{\"type\":\"any\"}}]}]}}";
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"" + userid + "\", \"policy\" :[{\"object\":{\"type\":\"so\",\"id\":\"13412341234123412341324\"},\"flows\":[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}]}}"; 
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

	 /**
	  * 
	  * @return UserInfo
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode getUserInfo() throws JsonProcessingException, IOException {
	    String string = "{\"id\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"username\":\"secServer02\",\"lastModified\":1433946242000,\"random_auth_token\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"approvedMemberships\":[{\"id\":\"387cff5e-747f-4a1c-a43a-defcb7244fa6\",\"user_id\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"role\":\"ADMIN\",\"group_id\":\"41c06ee3-12d5-41d2-9317-398953219ac3\",\"group_name\":\"grouptest\",\"user_name\":\"secServer02\",\"lastModified\":1444313143000}]}"; 
	    ObjectMapper mapper = new ObjectMapper();
	    JsonNode so_data;
		so_data = mapper.readTree(string);
		return so_data;
	}
	 
	 /**
	  * 
	  * @return UserInfo
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode getUserInfo(String id) throws JsonProcessingException, IOException {
	    String string = "{\"id\":\"" + id + "\",\"username\":\"secServer02\",\"lastModified\":1433946242000,\"random_auth_token\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"approvedMemberships\":[{\"id\":\"387cff5e-747f-4a1c-a43a-defcb7244fa6\",\"user_id\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"role\":\"ADMIN\",\"group_id\":\"41c06ee3-12d5-41d2-9317-398953219ac3\",\"group_name\":\"grouptest\",\"user_name\":\"secServer02\",\"lastModified\":1444313143000}]}"; 
	    ObjectMapper mapper = new ObjectMapper();
	    JsonNode so_data;
		so_data = mapper.readTree(string);
		return so_data;
	}


}
