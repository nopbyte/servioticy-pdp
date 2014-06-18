package de.passau.uni.sec.compose.pdp.servioticy.idm;

import com.fasterxml.jackson.databind.JsonNode;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

public class IdentityVerifier 
{

    public void verifyWebTokenApiToken(JsonNode serviceObjectMetadata, String apiToken) throws PDPServioticyException
    {
    	JsonNode token = serviceObjectMetadata.get("api_token");
    	String tokenString = token.asText();
    	if(!tokenString.equals(apiToken))
    		throw new PDPServioticyException(403, "The web object has presented the wrong API_TOKEN", "Wrong API_TOKEN provided for serviceObjectMetadata for SO with id: "+serviceObjectMetadata.get("id").toString());
    }
}
