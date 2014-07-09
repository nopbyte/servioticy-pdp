package de.passau.uni.sec.compose.pdp.servioticy;
import com.fasterxml.jackson.databind.JsonNode;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IdentityVerifier;
import de.passau.uni.sec.compose.pdp.servioticy.provenance.ServioticyProvenance;

public class LocalPDP implements PDP
{

	private IdentityVerifier id;
	
	public LocalPDP()
	{
		id = new IdentityVerifier();
	}
	
	@Override
	public PermissionCacheObject checkAuthorization(String token,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			operationID opId) throws PDPServioticyException {
		
		if(opId.equals(PDP.operationID.SendDataToServiceObject))
		{
			//TODO complete
			id.verifyWebTokenApiToken(security_metadata_SO_current, token);
		}
		else if (opId.equals(PDP.operationID.SendDataToServiceObjectProv))
		{
			PermissionCacheObject ret = new PermissionCacheObject();
			// Get initial Provenance
			try{
				ret.setCache(ServioticyProvenance.getInitialProvenance(security_metadata_SO_current));
			} catch (Exception e) {
				throw new PDPServioticyException(400, "The parameters for SendDataToServiceObjectProv were wrong. ", "Wrong parameters");
			    
			}
			return ret;	
		}
		return null;
	}
	
	
}
