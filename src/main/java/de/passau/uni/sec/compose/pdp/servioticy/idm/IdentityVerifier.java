package de.passau.uni.sec.compose.pdp.servioticy.idm;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

public class IdentityVerifier 
{
	private static final String IDM_USER_SECTION = "id";


    public JsonNode verifyWebTokenApiToken(JsonNode serviceObjectMetadata, String apiToken) throws PDPServioticyException
    {
    	JsonNode ret = null;
    	// Verify token
    	JsonNode token = serviceObjectMetadata.findValue("api_token");
    	String tokenString = token.asText();
    	if(!tokenString.equals(apiToken))
    		throw new PDPServioticyException(403, "The web object has presented the wrong API_TOKEN", "Wrong API_TOKEN provided for serviceObjectMetadata for SO with id: "+serviceObjectMetadata.get("id").toString());
    	// Build Security Meta-Data
    	ObjectMapper mapper = new ObjectMapper();
    	//ObjectNode node =  mapper.getNodeFactory().objectNode();
    	ObjectNode securityData = mapper.getNodeFactory().objectNode();
    	JsonNode policies = serviceObjectMetadata.findPath("policy");
    	if (policies !=  null){
	    	securityData.put("policy", policies);
	    	//node.put("security", securityData);
	    	ret = securityData;
    	}
    	return ret;
    }
    public String userIdFromToken(String accessToken,String idmHost, String idmUser, String idmPass,int idmPort)
    {
    	String response = "";
    	IDMCommunicator com = new IDMCommunicator(idmUser, idmPass, idmHost, idmPort);
		 try {
			 response = com.getInformationForUser(accessToken);
		 }
		 catch (PDPServioticyException e){
			 return "";
		 }
		// Parse response
	    ObjectMapper mapperUser = new ObjectMapper();
	    JsonNode user_data = null;
		try {
			user_data = mapperUser.readTree(response);
		} catch (JsonProcessingException e1) {
			user_data = null;
		} catch (IOException e1) {
			user_data = null;
		}
		JsonNode userSO = user_data.findValue(IDM_USER_SECTION);
		return userSO.asText();
    }
}
