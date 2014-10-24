package de.passau.uni.sec.compose.pdp.servioticy.provenance;

import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.security.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.reputation.Source;

public class ServioticyProvenance 
{

    public static JsonNode getInitialProvenance(JsonNode serviceObjectMetadata) throws PDPServioticyException
    {
	//JsonNode ret = rootNode.path("provenance");
		if (serviceObjectMetadata != null)
		{
			// extract entity
			JsonNode entityJSON = serviceObjectMetadata.findValue("id");
	
			// extract onbehalf
			JsonNode owner_id = serviceObjectMetadata.findValue("owner_id");
			// extract policy
			JsonNode policy = serviceObjectMetadata.findValue("policy");
	
			// get source
			String source = "";
	
			// generate timestamp
			Date date= new Date();
			long time = date.getTime();
			String timestamp = Long.toString(time);
	
			String stringMetaData = "{";
			// Add security metadata for the SU
			// build inital provenance data
			stringMetaData +=  "\"provenance\":{\"agent\" : \"SO\", \"type\": \"sensor_update\", \"entity\":\""+ entityJSON.asText() + "\", \"activity\" : \"creation\", \"timestamp\":" + timestamp + ",\"accessed\":\"\", \"onbehalf\":\"" + owner_id.asText() + "\", \"source\":\"" + source + "\"}";
			stringMetaData += ",\"policy\":" + policy;
			stringMetaData += "}";
			ObjectMapper mapper = new ObjectMapper();
			JsonNode so_data;
			try{
				so_data = mapper.readTree(stringMetaData);
				return so_data;
			}
			catch (IOException e)
			{
				throw new PDPServioticyException(400, "The parameters for SendDataToServiceObject were wrong. ", "Wrong parameters");
			}
		}
		else
		{
			throw new PDPServioticyException(400, "The parameters for SendDataToServiceObject were wrong. ", "Wrong parameters");
		}
    }
    public JsonNode getSourceFromSecurityMetaDataJsonNode(String SU_securityMetadata) throws PDPServioticyException
    {
    	ObjectMapper mapper = new ObjectMapper();
    	JsonNode root = mapper.createObjectNode();
    	
		try {
			//TODO fix once provenance is mandatory
			if(SU_securityMetadata==null||SU_securityMetadata.equals(""))
			{
				((ObjectNode)root).put("soid","");
				((ObjectNode)root).put("streamid", "");
				return root;
			}
			JsonNode security = mapper.readTree(SU_securityMetadata);
			JsonNode provenance = security.findValue("provenance");
			if(provenance != null)
			{
				
			  JsonNode soId = provenance.get("entity");
			  JsonNode stream = provenance.get("so-stream");
			  ((ObjectNode)root).put("soid",soId);
			  ((ObjectNode)root).put("streamid", stream);
			}
			return root;
			
		} catch (JsonProcessingException e) {
			 throw new PDPServioticyException(500, "Wrong format in security metadata. ", "Wrong parameters. JsonProcessingException for string: "+SU_securityMetadata);
		} catch (IOException e) {
			throw new PDPServioticyException(500, "Wrong format in security metadata. ", "Wrong parameters. IOException while reading string: "+SU_securityMetadata);
		}
    }
 
    
    public String getSourceFromSecurityMetaDataAsString(String SU_securityMetadata) throws PDPServioticyException
    {
    	return getSourceFromSecurityMetaDataJsonNode(SU_securityMetadata).toString();	
    }
}
