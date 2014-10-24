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

public class TestDeleteData
{
	 private static final String IDM_USER = "component";
	private static final int IDM_PORT = 8080;
	private static final String IDM_PASS = "ZXJpZHMiLCJ";
	private static final String IDM_HOST = "132.231.11.217";
	private PDP pdp;

	 @Before
	 public void setUp()
	 {
		 pdp = new LocalPDP();
		 pdp.setIdmUser(IDM_USER);
		 pdp.setIdmPort(IDM_PORT);
		 pdp.setIdmPassword(IDM_PASS);
		 pdp.setIdmHost(IDM_HOST);
	 }


	 @Test
	 public  void DeleteServiceObjectDataCacheIDM() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret=null;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode su_data = buildJsonSuMetadataPublic();
				// Get token
				 IDMCommunicator com = new IDMCommunicator(IDM_USER, IDM_PASS, IDM_HOST, 8080);
				CloseableHttpResponse responsePost = com.sendPostToIDM("/auth/user/","{\"username\" : \"test2\",\"password\" : \"pass\"}");
				ObjectMapper mapper = new ObjectMapper();
				JsonNode response= mapper.readTree(EntityUtils.toString(responsePost.getEntity()));
			    com.clear();

				JsonNode accesToken = response.findValue("accessToken");
				IdentityVerifier idm = new IdentityVerifier();
				String uid = idm.userIdFromToken(accesToken.asText(), IDM_HOST, IDM_USER, IDM_PASS, IDM_PORT);
				JsonNode so_data = buildJsonSoMetadata(uid);
				//watch for the output! it should get the token for this only once
				System.out.println("initiating cache test!");
				for(int i =0;i<3;i++)
				{
				
				  // verify if delete is possible
				  ret = pdp.checkAuthorization(accesToken.asText(), so_data, su_data, ret, PDP.operationID.DeleteSensorUpdateData);
				  //ret = ServioticyProvenance.getInitialProvenance(so_data);
				  // Check the result of the policy evaluation
				  boolean pdpResult = ret.isPermission();
				  //assertEquals(ret.getUserId(), "92f83ea4-2835-4dce-a34a-5711d948c610");
				  assertEquals(true, pdpResult);
				}
				System.out.println("end of cache test!");
			} catch (PDPServioticyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				fail();
			}
	 }
	 
	 
	 @Test
	 public  void DeleteServiceObjectDataCacheNotOKIDM() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode su_data = buildJsonSuMetadataPublic();
				// Get token
				 IDMCommunicator com = new IDMCommunicator(IDM_USER, IDM_PASS, IDM_HOST, 8080);
				CloseableHttpResponse responsePost = com.sendPostToIDM("/auth/user/","{\"username\" : \"test2\",\"password\" : \"pass\"}");
				ObjectMapper mapper = new ObjectMapper();
				JsonNode response= mapper.readTree(EntityUtils.toString(responsePost.getEntity()));
			    com.clear();

				JsonNode accesToken = response.findValue("accessToken");
				IdentityVerifier idm = new IdentityVerifier();
				JsonNode so_data = buildJsonSoMetadata("someotherid");
				
				// Get initial provenance
				ret = pdp.checkAuthorization(accesToken.asText(), so_data, su_data, null, PDP.operationID.DeleteSensorUpdateData);
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
	 
	 @Test
	 public  void DeleteServiceObjectDataCacheInvalidTokenIDM() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode su_data = buildJsonSuMetadataPublic();
				// Get token
				 IDMCommunicator com = new IDMCommunicator(IDM_USER, IDM_PASS, IDM_HOST, 8080);
				
				IdentityVerifier idm = new IdentityVerifier();
				JsonNode so_data = buildJsonSoMetadata("someotherid");
				
				// Get initial provenance
				ret = pdp.checkAuthorization("randomtoken", so_data, su_data, null, PDP.operationID.DeleteSensorUpdateData);
				//ret = ServioticyProvenance.getInitialProvenance(so_data);
				// Check the result of the policy evaluation
				System.out.println("IDM" + ret.getUserId());
				boolean pdpResult = ret.isPermission();
				assertEquals(ret.getUserId(), null);
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
	 private JsonNode buildJsonSoMetadata(String owner) throws JsonProcessingException, IOException {
		     String string = "{\"security\" : {\"id\":\"13412341234123412341324\", \"api_token\": \"asdfasdfasdf\", \"owner_id\":\""+owner+"\", \"policy\" :[{\"flow\" : { \"forall\" : \"entities\", \"target\" : \"entities\" }},{\"flow\" : { \"forall\" : \"entities\", \"source\" : \"entities\" }}]}}";
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
