var pgp = require("node-pgp");
var Filter = pgp.Keyring.Filter;

Filter.Equals.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length;

	if(this.__value == null)
		return fieldName+" IS NULL";
	else
	{
		args.push(this.__value);
		return fieldName+" = $"+i;
	}
};

Filter.LessThan.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length;
	args.push(this.__value);

	return fieldName+" < $"+i;
};

Filter.LessThanOrEqual.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length;
	args.push(this.__value);

	return fieldName+" <= $"+i;
};

Filter.GreaterThan.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length;
	args.push(this.__value);

	return fieldName+" > $"+i;
};

Filter.GreaterThanOrEqual.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length;
	args.push(this.__value);

	return fieldName+" >= $"+i;
};

Filter.Not.prototype.toPostgresCondition = function(fieldName, args) {
	var subCondition = (this.__filter.toPostgresCondition ? this.__filter.toPostgresCondition(fieldName, args) : null);
	if(subCondition == null)
		return null;
	else
		return "NOT ( "+subCondition+" )";
};

Filter.Or.prototype.toPostgresCondition = function(fieldName, args) {
	return _join(this.__filters, fieldName, args, " OR ");
};

Filter.And.prototype.toPostgresCondition = function(fieldName, args) {
	return _join(this.__filters, fieldName, args, " AND ");
};

function _join(filters, fieldName, args, separator)
{
	var subConditions = [ ];
	for(var i=0; i<this.__filters.length; i++)
	{
		var subCondition = (this.__filters[i].toPostgresCondition ? this.__filters[i].toPostgresCondition(fieldName, args) : null);
		if(subCondition == null)
			return null;
		subConditions.push(subCondition);
	}
	return subConditions.join(" OR ");
}