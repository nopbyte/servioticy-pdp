package de.passau.uni.sec.compose.pdp.servioticy.exception;

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
	
	
}
