package de.passau.uni.sec.compose.pdp.servioticy;

import java.util.HashMap;
import java.util.Map;

public class PermissionCacheObject
{
	private boolean permission =false;
	private Object cache;
	public boolean isPermission() {
		return permission;
	}
	public void setPermission(boolean permission) {
		this.permission = permission;
	}
	public Object getCache() {
		return cache;
	}
	public void setCache(Object cache) {
		this.cache = cache;
	}
	public String getUserId()
	{
		Map temp = (Map<String, Object>)this.cache;
		String ret = (String) temp.get("UserId");
		return ret;
	}
	
}
