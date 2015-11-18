package de.passau.uni.sec.compose.pdp.servioticy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import iotp.model.storage.model.EncodedAttributeValue;
import iotp.model.storage.model.EncodedMembership;
import iotp.model.storage.model.EncodedUser;

import java.io.IOException;
import java.util.Date;
import java.util.LinkedList;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.authz.AuthorizationServioticy;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.policy.PolicyEvaluation;

public class TestDefaultPolicyJS {
	private PolicyEvaluation pdp; 
	
	 @Before
	 public void setUp()
	 {
		 pdp = new PolicyEvaluation();

	 }
	
	 @Test
	 public  void wrongUIDinPolicy() throws PDPServioticyException
	 {
		 	System.out.println("wrongUIDinPolicy");
		  	boolean ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPrivate2(token, "123");
				JsonNode su_data = buildJsonSuMetadataPrivate2("123"); // changes the user id
				// Get initial provenance
				System.out.println("SO: " + so_data);
				System.out.println("SU: " + su_data);
				ret = pdp.checkFlow(so_data, su_data, "weather");
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				assertEquals(false, ret);
			} catch (IOException e) {
				fail();
			}	
	 }
	 
	 @Test
	 public  void publicSOpublicSU() throws PDPServioticyException
	 {
		 	System.out.println("publicSOpublicSU");
		  	boolean ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPublic(token);
				JsonNode su_data = buildJsonSuMetadataPublic(); // changes the user id
				// Get initial provenance
				System.out.println("SO: " + so_data);
				System.out.println("SU: " + su_data);
				ret = pdp.checkFlow(so_data, su_data, "weather");
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				assertEquals(true, ret);
			} catch (IOException e) {
				fail();
			}	
	 }
	 
	 @Test
	 public  void publicSUuserX() throws PDPServioticyException
	 {
		 	System.out.println("publicSUuserX");
		  	boolean ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode su_data = buildJsonSuMetadataPublic();
				JsonNode userInfo = buildJsonUserInfo();
				// Get initial provenance
				System.out.println("SU: " + su_data);
				ret = pdp.checkAccess(su_data, "X", userInfo);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				assertEquals(true, ret);
			} catch (IOException e) {
				fail();
			}	
	 }
	 
	 @Test
	 public  void privateSUuserWrong() throws PDPServioticyException
	 {
		 	System.out.println("privateSUuserWrong");
		  	boolean ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode su_data = buildJsonSuMetadataPrivate("123");
				JsonNode userInfo = buildJsonUserInfo();
				// Get initial provenance
				System.out.println("SU: " + su_data);
				ret = pdp.checkAccess(su_data, "X", userInfo);
				// Check the result of the policy evaluation
				assertEquals(false, ret);
			} catch (IOException e) {
				fail();
			}	
	 }
	 
	 @Test
	 public  void privateSUuserRight() throws PDPServioticyException
	 {
		 	System.out.println("privateSUuserRight");
		  	boolean ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode su_data = buildJsonSuMetadataPrivate("secServer02");
				JsonNode userInfo = buildJsonUserInfo();
				// Get initial provenance
				System.out.println("SU: " + su_data);
				ret = pdp.checkAccess(su_data, "secServer02", userInfo);
				// Check the result of the policy evaluation
				assertEquals(true, ret);
			} catch (IOException e) {
				System.out.println("Error: " + e);
				fail();
			}	
	 }
	 
	 @Test
	 public  void testPublicOTP() throws PDPServioticyException
	 {
		 	System.out.println("privateSUuserRight");
		 	AuthorizationServioticy tempAuth = new AuthorizationServioticy(pdp);
		 	EncodedUser user = new EncodedUser();
		 	user = fillUser(user);
		  	boolean ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPublic("asd");
				JsonNode userInfo = buildJsonUserInfo();
				// Get initial provenance
				System.out.println("SO: " + so_data);
				ret = tempAuth.evaluatePolicy(user, so_data,"weather");
				// Check the result of the policy evaluation
				assertEquals(true, ret);
			} catch (IOException e) {
				fail();
			}
	 }
	 
	 
	 private EncodedUser fillUser(EncodedUser user) {
		 	user.setId("id");
		 	user.setLastModified(new Date());
		 	user.setRandom_auth_token("random_auth_token");
		 	user.setUsername("username");
		 	// Attributes
		 	LinkedList<EncodedAttributeValue> eal = new LinkedList();
		 	EncodedAttributeValue eav1 = new EncodedAttributeValue();
		 	eav1.setApproved(true);
		 	eav1.setAttribute_definition_id("attribute_definition_id");
		 	eav1.setEntity_id("entity_id");
		 	eav1.setEntity_type("entity_type");
		 	eav1.setGroup_id("group_id");
		 	eav1.setOwner_id("owner_id");
		 	eal.add(eav1);
		 	EncodedAttributeValue eav2 = new EncodedAttributeValue();
		 	eav2.setApproved(true);
		 	eav2.setAttribute_definition_id("attribute_definition_id2");
		 	eav2.setEntity_id("entity_id2");
		 	eav2.setEntity_type("entity_type2");
		 	eav2.setGroup_id("group_id2");
		 	eav2.setOwner_id("owner_id2");
		 	eal.add(eav2);
		 	// Memberships
		 	LinkedList<EncodedMembership> ams = new LinkedList();
		 	EncodedMembership ems1 = new EncodedMembership();
		 	ems1.setGroup_name("group_name");
		 	ems1.setGroup_id("group_id");
		 	ems1.setId("id");
		 	ems1.setLastModified(new Date());
		 	ems1.setRole("role");
		 	ems1.setUser_id("user_id");
		 	ems1.setUser_name("user_name");
		 	ams.add(ems1);
		 	
		 	user.setApprovedMemberships(ams);
		 	user.setApprovedAttributes(eal);
		 	return user;
	}

	/**
	  * 
	  * @param token
	  * @return SO with public policy 
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSoMetadataPrivate(String token, String userid) throws JsonProcessingException, IOException {
		     String string = "{\"security\" : {\"id\":\"123\", \"api_token\": \""+token+"\", \"owner_id\":\"" + userid + "\", \"policy\" :[{\"object\":{\"type\":\"so\",\"id\":\"123\"},\"flows\":[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}]}}"; 
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
		     String string = "{\"security\" : {\"id\":\"123\",\"owner_id\":\""+ userid + "\", \"policy\" :[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}}";
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
		     String string = "{\"security\" : {\"id\":\"123\", \"api_token\": \""+token+"\", \"owner_id\":\"owner_identifier123123\", \"policy\" :[{\"object\":{\"type\":\"so\",\"id\":\"123\"},\"flows\":[{\"source\":{\"type\":\"any\"}},{\"target\":{\"type\":\"any\"}}]}]}}";
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
		     String string = "{\"security\" : {\"id\":\"123\",\"owner_id\":\"owner_identifier123123\", \"policy\" :[{\"source\":{\"type\":\"any\"}},{\"target\":{\"type\":\"any\"}}]}}";
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
		     String string = "{\"security\" : {\"id\":\"123\", \"api_token\": \""+token+"\", \"owner_id\":\"" + userid + "\", \"policy\" :[{\"object\":{\"type\":\"so\",\"id\":\"123\"},\"flows\":[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}]}}"; 
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
	     String string = "{\"security\" : {\"id\":\"123\", \"owner_id\":\"" + userid + "\", \"policy\" :[{\"source\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"source\":{\"type\":\"any\",\"name\":\"{$src}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$src.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]},{\"target\":{\"type\":\"user\",\"id\":\"" + userid +"\"},\"locks\":[]},{\"target\":{\"type\":\"any\",\"name\":\"{$trg}\"},\"locks\":[{\"path\":\"locks/actsFor\",\"args\":[{\"type\":\"any\",\"id\":\"{$trg.id}\"},{\"type\":\"user\",\"id\":\"" + userid +"\"}]}]}]}}"; 
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
	 private JsonNode buildJsonUserInfo() throws JsonProcessingException, IOException {
		 String string = "{\"id\":\"secServer02\",\"username\":\"secServer02\",\"lastModified\":1433946242000,\"random_auth_token\":\"peV5vkhP4KrWSs84M7EjXdhzW0ylgqWfjIf5UM\",\"approvedMemberships\":[{\"id\":\"387cff5e-747f-4a1c-a43a-defcb7244fa6\",\"user_id\":\"ade0456b-af8b-4348-b640-adfb51e9c02b\",\"role\":\"ADMIN\",\"group_id\":\"41c06ee3-12d5-41d2-9317-398953219ac3\",\"group_name\":\"grouptest\",\"user_name\":\"secServer02\",\"lastModified\":1444313143000}]}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}
	

}
