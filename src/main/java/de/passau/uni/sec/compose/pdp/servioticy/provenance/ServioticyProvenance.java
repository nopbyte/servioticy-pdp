package de.passau.uni.sec.compose.pdp.servioticy.provenance;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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
    /**
     * This method regturns the source including soid and stream that provided the sensor update containing the SU_securityMetadata
     * @param SU_securityMetadata
     * @return
     * @throws PDPServioticyException
     */
    public Source getSourceFromSecurityMetaData(String SU_securityMetadata) throws PDPServioticyException
    {
    	Source src = new Source();
    	ObjectMapper mapper = new ObjectMapper();
		try {
			//TODO fix once provenance is mandatory
			if(SU_securityMetadata==null||SU_securityMetadata.equals(""))
				return src;
			JsonNode security = mapper.readTree(SU_securityMetadata);
			JsonNode provenance = security.findValue("provenance");
			if(provenance != null)
			{
			  JsonNode soId = provenance.get("entity");
			  JsonNode stream = provenance.get("so-stream");
			  if(soId!=null && stream!=null)
			  {
				 src.setSoid(soId.asText());
			     src.setStreamid(stream.asText());
			  }
			}
			
		} catch (JsonProcessingException e) {
			 throw new PDPServioticyException(500, "Wrong format in security metadata. ", "Wrong parameters. JsonProcessingException for string: "+SU_securityMetadata);
		} catch (IOException e) {
			throw new PDPServioticyException(500, "Wrong format in security metadata. ", "Wrong parameters. IOException while reading string: "+SU_securityMetadata);
		}
				
    	return src;
    }
}
