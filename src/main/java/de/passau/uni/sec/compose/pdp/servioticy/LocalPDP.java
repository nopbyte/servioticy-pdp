package de.passau.uni.sec.compose.pdp.servioticy;
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
		else if(opId.equals(PDP.operationID.RetrieveServiceObjectData))
		{
		    AuthorizationServioticy authz= new AuthorizationServioticy();
		    return authz.verifyGetData(token, security_metadata_SO_current, security_metadata_of_the_SU, cache, this.idmHost, this.idmUser,this.idmPassword, idmPort);
		}
		else if (opId.equals(PDP.operationID.DispatchData))
		{
		    AuthorizationServioticy authz= new AuthorizationServioticy();
		    return authz.verifyGetDataDispatch(token, security_metadata_SO_current, security_metadata_of_the_SU, cache, this.idmHost, this.idmUser,this.idmPassword, idmPort);
		}
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
