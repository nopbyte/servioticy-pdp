package de.passau.uni.sec.compose.pdp.servioticy.idm;

import static org.junit.Assert.*;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.util.EntityUtils;
import org.junit.rules.ExpectedException.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.List;
import java.util.LinkedList;

import javax.sound.midi.SysexMessage;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.passau.uni.sec.compose.pdp.servioticy.LocalPDP;
import de.passau.uni.sec.compose.pdp.servioticy.PDP;
import de.passau.uni.sec.compose.pdp.servioticy.PermissionCacheObject;
import de.passau.uni.sec.compose.pdp.servioticy.provenance.ServioticyProvenance;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IDMCommunicator;

import com.jayway.jsonpath.Criteria;
import com.jayway.jsonpath.Filter;
import com.jayway.jsonpath.JsonPath;

public class TestGetData
{
	 private PDP pdp;

	 @Before
	 public void setUp()
	 {
		 pdp = new LocalPDP();
		 pdp.setIdmUser("component");
		 pdp.setIdmPort(8080);
		 pdp.setIdmPassword("ZXJpZHMiLCJ");
		 pdp.setIdmHost("132.231.11.217");
	 }


	 @Test
	 public  void RetrieveServiceObjectDataCachePublicIDM() throws PDPServioticyException
	 {
		  	PermissionCacheObject ret;
			try {
				// Generate input
				String token=UUID.randomUUID().toString();
				JsonNode so_data = buildJsonSoMetadataPublic(token);
				JsonNode su_data = buildJsonSuMetadataPublic();
				// Get token
				 IDMCommunicator com = new IDMCommunicator("component", "ZXJpZHMiLCJ", "132.231.11.217", 8080);
				CloseableHttpResponse responsePost = com.sendPostToIDM("/auth/user/","{\"username\" : \"test2\",\"password\" : \"pass\"}");
				ObjectMapper mapper = new ObjectMapper();
			    JsonNode response;
				so_data = mapper.readTree(EntityUtils.toString(responsePost.getEntity()));
			    com.clear();

				JsonNode accesToken = so_data.findValue("accessToken");
				// Get initial provenance
				ret = pdp.checkAuthorization(accesToken.asText(), so_data, su_data, null, PDP.operationID.RetrieveServiceObjectData);
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
