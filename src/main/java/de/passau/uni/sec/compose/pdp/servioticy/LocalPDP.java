package de.passau.uni.sec.compose.pdp.servioticy;
import com.fasterxml.jackson.databind.JsonNode;

import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;

public class LocalPDP implements PDP
{

	@Override
	public PermissionCacheObject checkAuthorization(String AuthToken,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			operationID opId) throws PDPServioticyException {
		// TODO Auto-generated method stub
		return null;
	}
	
	
}
