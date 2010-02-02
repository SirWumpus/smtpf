<?
function time62Encode($time)
{
	$base62_chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

	$local = localtime_r($time, true);

	$buffer = '';
	$buffer[0] = $base62[$local['tm_year'] % 62];
	$buffer[1] = $base62[$local['tm_mon']];
	$buffer[2] = $base62[$local['tm_mday'] - 1];
	$buffer[3] = $base62[$local['tm_hour']];
	$buffer[4] = $base62[$local['tm_min']];
	$buffer[5] = $base62[$local['tm_sec']];

	return $buffer;
}

function time62Decode($time_encoding)
{
	$base62_chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
	$localtime = localtime(time(),true);
	$localtime['tm_year'] -= $localtime['tm_year'] % 62;

	if (($value = strpos($base62_chars, $time_encoding[0])) === false)
		return 0;
	$localtime['tm_year'] += $value;

	if (($value = strpos($base62_chars, $time_encoding[1])) === false)
		return 0;
	$localtime['tm_mon'] = $value + 1;

	if (($value = strpos($base62_chars, $time_encoding[2])) === false)
		return 0;
	$localtime['tm_mday'] = $value + 1;

	if (($value = strpos($base62_chars, $time_encoding[3])) === false)
		return 0;
	$localtime['tm_hour'] = $value;

	if (($value = strpos($base62_chars, $time_encoding[4])) === false)
		return 0;
	$localtime['tm_min'] = $value;

	if (($value = strpos($base62_chars, $time_encoding[5])) === false)
		return 0;
	$localtime['tm_sec'] = $value;

	return mktime(
		$localtime['tm_hour'], $localtime['tm_min'], $localtime['tm_sec'],
		$localtime['tm_mon'], $localtime['tm_mday'], $localtime['tm_year']+1900
	);
}
?>