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
	 public  void defaultpolicyPublic() throws PDPServioticyException
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
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPublic(token);
				JsonNode su_data = buildJsonSuMetadataPublic();
				inputCache.setCache("{\"username\" : \"123Test\"}");	
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
		  	PermissionCacheObject ret;
			PermissionCacheObject inputCache = new PermissionCacheObject();
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPrivate(token, "123");
				JsonNode su_data = buildJsonSuMetadataPrivate("123");
				inputCache.setCache("{\"username\" : \"123\"}");	
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
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPrivate(token, "123");
				JsonNode su_data = buildJsonSuMetadataPrivate("123");
				inputCache.setCache("{\"username\" : \"123False\"}");	
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



	 /**
	  * 
	  * @param token
	  * @return SO with public policy 
	  * @throws JsonProcessingException
	  * @throws IOException
	  */
	 private JsonNode buildJsonSoMetadataPrivate(String token, String userid) throws JsonProcessingException, IOException {
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\",\"owner_id\":\""+ userid + "\", \"policy\" :[{\"flow\" : { \"target\" : \"userid/" + userid + "\" }},{\"flow\" : { \"source\" : \"userid/" + userid + "\" }}]}}";
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \""+token+"\", \"owner_id\":\"owner_identifier123123\", \"policy\" :[{\"flow\" : { \"forall\" : \"entities\", \"target\" : \"entities\" }},{\"flow\" : { \"forall\" : \"entities\", \"source\" : \"entities\" }}]}}";
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
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\",\"owner_id\":\"owner_identifier123123\", \"policy\" :[{\"flow\" : { \"forall\" : \"entities\", \"target\" : \"entities\" }},{\"flow\" : { \"forall\" : \"entities\", \"source\" : \"entities\" }}]}}";
		    ObjectMapper mapper = new ObjectMapper();
		    JsonNode so_data;
			so_data = mapper.readTree(string);
			return so_data;
	}

}
