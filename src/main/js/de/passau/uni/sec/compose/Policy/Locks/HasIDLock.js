/**
 * Copyright 2015 Daniel Schreckling
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

"use strict";

if(global && typeof print !== "function") {
    var PolicyConfig = require("./../PolicyConfig.js");
    var Lock = require(PolicyConfig.rootDir + "./../Lock.js");
    var system = require(PolicyConfig.rootDir + "./../system.js");
}

var HasIDLock = function(lock) {
    // call the super class constructor
    HasIDLock.super_.call(this, lock);
};

Lock.registerLock("hasID", HasIDLock);

system.inherits(HasIDLock, Lock);

HasIDLock.prototype.copy = function() {
    var c = new HasIDLock(this);
    return c;
}

HasIDLock.prototype.isOpen = function(context) {
    if(context) {
		if(context.subject.type == 'node') {
			return { result : (this.args[0] === context.subject.node.id), conditional : false };
		} else {
			return { result : true, conditional : false };
		}
	} else {
		throw new Error("HasIDLock: Unable to evaluate lock without context");
    }
}

HasIDLock.prototype.lub = function(lock) {
    if(this.eq(lock))
		return this;
    else {
        if(this.path == lock.path)
            return Lock.closedLock();
        else
            return null;
    }
}

if(global && typeof print !== "function")
    module.exports = HasIDLock;
