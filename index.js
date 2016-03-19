var async = require('async');
var helpers = module.parent.require('./privileges/helpers');

exports.filterModerator = function(data, callback) {
	if (Array.isArray(data.uid)) {
		return async.forEachOf(data.uid, function(uid, i, next) {
			var isModerator = [data.isModerator[i]];
			filter(uid, data.cid, isModerator, function(err) {
				if (err) {
					return next(err);
				}
				data.isModerator[i] = isModerator[0];
				next(null);
			});
		}, function(err) {
			if (err) {
				return callback(err);
			}
			callback(null, data);
		});
	}

	if (!Array.isArray(data.cid)) {
		var isModerator = [data.isModerator];
		return filter(data.uid, data.cid, isModerator, function(err) {
			if (err) {
				return callback(err);
			}
			data.isModerator = isModerator[0];
			callback(null, data);
		});
	}

	filter(data.uid, data.cid, data.isModerator, function(err) {
		if (err) {
			return callback(err);
		}
		callback(null, data);
	});
};

function filter(uid, cids, isModerator, callback) {
	helpers.isUserAllowedTo('read', uid, Array.isArray(cids) ? cids : [cids], function(err, results) {
		if (err) {
			return callback(err);
		}

		if (Array.isArray(cids)) {
			for (var i = 0; i < results.length; i++) {
				isModerator[i] = isModerator[i] && results[i];
			}
		} else {
			isModerator[0] = isModerator[0] && results[0];
		}
		callback(null);
	});
}
