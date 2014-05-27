package start;



import de.passau.uni.sec.compose.pdp.servioticy.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.exception.LocalPDP;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDP;

public class PDPCall {
  public static void main(String[] args) {
	  
	  	PDP pdp = new LocalPDP();
	  	try {
			System.out.println("calling the PDP");
	  		pdp.checkAuthorization(null, null, null, null, PDP.operationID.CreateNewSubscription);
			
		} catch (PDPServioticyException e) 
		{
			System.out.println("User message: "+ e.getMessage()+",  log message: "+e.getLogInfo()+ ",HTTP error code: "+e.getStatus());
			
		}
	  
  }
}