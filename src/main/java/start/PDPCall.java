package start;



import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;

import de.passau.uni.sec.compose.pdp.servioticy.LocalPDP;
import de.passau.uni.sec.compose.pdp.servioticy.PDP;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

public class PDPCall {
  PDP pdp;
  
  public PDPCall() {
		pdp = new LocalPDP();		  
  }
  public static void main(String[] args) {
	  
	  	try {
	  		PDPCall obj = new PDPCall();
			obj.postDataToSOCall();
	  		
		} catch (PDPServioticyException e) 
		{
			System.out.println("User message: "+ e.getMessage()+",  log message: "+e.getLogInfo()+ ",HTTP error code: "+e.getStatus());
			
		}
	  
  }

  private  void postDataToSOCall() throws PDPServioticyException
  {
	    //String jsondata = "{\"id\":\"serviceObject_id1\", \"api_token\":\"Avcedse2df23sdaxvc2ecads\"}";
	    
	    JsonNode so_data = null;
	    String token=UUID.randomUUID().toString();
	    
		System.out.println("Testing expected success of idm check");
		//pdp.checkAuthorization(token, so_data, null, null, PDP.operationID.SendDataToServiceObjectProv);
		
  }
}
