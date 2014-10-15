package de.passau.uni.sec.compose.pdp.servioticy.provenance;

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
		String entity = "";
		Pattern entity_PATTERN = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
		Matcher entity_m = entity_PATTERN.matcher(serviceObjectMetadata.toString());
		entity_m.find();
		entity = entity_m.group(1);

		// extract onbehalf
		String onbehalf = "";
		Pattern onbehalf_PATTERN = Pattern.compile("\"owner_id\"\\s*:\\s*\"([^\"]+)\"");
		Matcher onbehalf_m = onbehalf_PATTERN.matcher(serviceObjectMetadata.toString());
		onbehalf_m.find();
		onbehalf = onbehalf_m.group(1);

		// get source
		String source = "";

		// generate timestamp
		Date date= new Date();
		long time = date.getTime();
		String timestamp = Long.toString(time);

		// build inital provenance data
		String string = "{\"provenance\":{\"agent\" : \"SO\", \"type\": \"sensor_update\", \"entity\":\""+ entity + "\", \"activity\" : \"creation\", \"timestamp\":" + timestamp + ",\"accessed\":\"\", \"onbehalf\":\"" + onbehalf + "\", \"source\":\"" + source + "\"}}";
		ObjectMapper mapper = new ObjectMapper();
		JsonNode so_data;
		try{
			so_data = mapper.readTree(string);
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
    
    public Source getSourceFromProvenanceData(String provenanceSensorUpdate)
    {
    	Source src = new Source();
    	
    	return src;
    }
}
