var pgp = require("node-pgp");
var Filter = pgp.Keyring.Filter;

Filter.Equals.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length+1;

	if(this.__rawValue == null)
		return fieldName+" IS NULL";
	else
	{
		args.push(this.__rawValue);
		return '"'+fieldName+'" = $'+i;
	}
};

Filter.EqualsIgnoreCase.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length+1;

	if(this.__rawValue == null)
		return fieldName+" IS NULL";
	else
	{
		args.push(this.__rawValue);
		return 'LOWER("'+fieldName+'") = LOWER($'+i+')';
	}
};

Filter.ContainsIgnoreCase.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length+1;

	args.push('%'+this.__rawValue+'%');
	return '"'+fieldName+'" ILIKE $'+i;
};

Filter.ShortKeyId.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length+1;

	args.push(this.__rawValue.toUpperCase());
	return 'SUBSTRING("'+fieldName+'" FROM 9 FOR 8) = $1';
};

Filter.LessThan.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length+1;
	args.push(this.__rawValue);

	return '"'+fieldName+'" < $'+i;
};

Filter.LessThanOrEqual.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length+1;
	args.push(this.__rawValue);

	return '"'+fieldName+'" <= $'+i;
};

Filter.GreaterThan.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length+1;
	args.push(this.__rawValue);

	return '"'+fieldName+'" > $'+i;
};

Filter.GreaterThanOrEqual.prototype.toPostgresCondition = function(fieldName, args) {
	var i = args.length+1;
	args.push(this.__rawValue);

	return '"'+fieldName+'" >= $'+i;
};

Filter.Not.prototype.toPostgresCondition = function(fieldName, args) {
	var subCondition = (this.__filter.toPostgresCondition ? this.__filter.toPostgresCondition(fieldName, args) : null);
	if(subCondition == null)
		return null;
	else
		return "NOT ( "+subCondition+" )";
};

Filter.Or.prototype.toPostgresCondition = function(fieldName, args) {
	return _join(this.__filters, fieldName, args, "OR");
};

Filter.And.prototype.toPostgresCondition = function(fieldName, args) {
	return _join(this.__filters, fieldName, args, "AND");
};

function _join(filters, fieldName, args, separator)
{
	var subConditions = [ ];
	for(var i=0; i<filters.length; i++)
	{
		var subCondition = (filters[i].toPostgresCondition ? filters[i].toPostgresCondition(fieldName, args) : null);
		if(subCondition == null)
			return null;
		subConditions.push(subCondition);
	}
	return "( "+subConditions.join(" "+separator+" ")+" )";
}