package de.passau.uni.sec.compose.pdp.servioticy;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;

import de.passau.uni.sec.compose.pdp.servioticy.authz.AuthorizationServioticy;
import de.passau.uni.sec.compose.pdp.servioticy.exception.PDPServioticyException;
import de.passau.uni.sec.compose.pdp.servioticy.idm.IdentityVerifier;
import de.passau.uni.sec.compose.pdp.servioticy.provenance.ServioticyProvenance;

public class LocalPDP implements PDP
{

	private IdentityVerifier id;
	
	private String idmHost;
	
	private int idmPort;
	
	private String idmUser;
	
	private String idmPassword;
	
	private AuthorizationServioticy authz;
	
	public LocalPDP()
	{
		id = new IdentityVerifier();
		 authz = new AuthorizationServioticy();
	}
	
	@Override
	public PermissionCacheObject checkAuthorization(String token,
			JsonNode security_metadata_SO_current,
			JsonNode security_metadata_of_the_SU, PermissionCacheObject cache,
			operationID opId) throws PDPServioticyException {
		
		if(opId.equals(PDP.operationID.SendDataToServiceObject)) 
		{
			Map<String, Object> tempMapCache = new HashMap<String, Object>();
			PermissionCacheObject ret = new PermissionCacheObject();

			// Checks the token and returns the security meta-data
			// the security metadata includes policy from the SO, and is inside the cache object.
			// 
			tempMapCache.put("SecurityMetaData", id.verifyWebTokenApiToken(security_metadata_SO_current, token));

			ret.setCache(tempMapCache);
			return ret;
		}
		else if (opId.equals(PDP.operationID.SendDataToServiceObjectProv)) // Initial provenance
		{ 
			//TODO Token not used
			PermissionCacheObject ret = new PermissionCacheObject();
			// Get initial Provenance
			try{
				ret.setCache(ServioticyProvenance.getInitialProvenance(security_metadata_SO_current));
			} catch (Exception e) {
				throw new PDPServioticyException(400, "The parameters for SendDataToServiceObjectProv were wrong. ", "Wrong parameters");
			    
			}
			return ret;	
		}
		else if(opId.equals(PDP.operationID.RetrieveServiceObjectData))
		{
		    //TODO SO not used
		    // Check policy (check parameters SU and authentikation token?) do the stuff with the cach object
		    
		    return authz.verifyGetData(token, security_metadata_SO_current, security_metadata_of_the_SU, cache, this.idmHost, this.idmUser,this.idmPassword, idmPort);
		}
		else if (opId.equals(PDP.operationID.DispatchData)) 
		{
		    // Check policy
		    return authz.verifyGetDataDispatch(security_metadata_SO_current, security_metadata_of_the_SU,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		}
		else if(opId.equals(PDP.operationID.GetUserInfo))
		{
			PermissionCacheObject ret = new PermissionCacheObject();
			ret.setCache(id.userIdFromToken(token,this.idmHost, this.idmUser,this.idmPassword, idmPort));
			return ret;
		}
		else if(opId.equals(PDP.operationID.RetrieveServiceObjectDescription))
			authz.retrieveSODescription(security_metadata_of_the_SU, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.UpdateServiceObject))
			return authz.updateSODescription(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.DeleteServiceObjectDescription))
			return authz.deleteSODescription(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if (opId.equals(PDP.operationID.retrieveSOStreams))
			return authz.retrieveSOStreams(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		else if(opId.equals(PDP.operationID.CreateNewSubscription))
			return authz.createSubscription(security_metadata_SO_current, token,this.idmHost, this.idmUser,this.idmPassword, idmPort);
		
		
		
				
		
		return null;
	}

	public IdentityVerifier getId() {
		return id;
	}

	public void setId(IdentityVerifier id) {
		this.id = id;
	}

	public String getIdmHost() {
		return idmHost;
	}

	public void setIdmHost(String idmHost) {
		this.idmHost = idmHost;
	}

	public String getIdmUser() {
		return idmUser;
	}

	public void setIdmUser(String idmUser) {
		this.idmUser = idmUser;
	}

	public String getIdmPassword() {
		return idmPassword;
	}

	public void setIdmPassword(String idmPassword) {
		this.idmPassword = idmPassword;
	}

	public int getIdmPort() {
		return idmPort;
	}

	public void setIdmPort(int idmPort) {
		this.idmPort = idmPort;
	}
	
	
	
	
}
