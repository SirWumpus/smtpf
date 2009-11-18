BEGIN {
	if (reset != 0) {
		last_msg = reset;
	} else {
		getline last_msg <"number_msg.txt"
		close "number_msg.txt"
	}
}

/LOG_MSG\(/ {
	if (reset || match($0, /000/)) {
		sub(/LOG_MSG\([0-9]+\)/, "LOG_MSG(" last_msg ")")
		last_msg++
	}
}
/LOG_NUM\(/ {
	if (reset || match($0, /000/)) {
		sub(/LOG_NUM\([0-9]+\)/, "LOG_NUM(" last_msg ")")
		last_msg++
	}
}
/LOG_TRACE0?\(/ {
	if (reset || match($0, /000,/)) {
		sub(/[0-9]+,/, last_msg ",")
		last_msg++
	}
}
/ID_MSG\(/ {
	if (reset || match($0, /000/)) {
		sub(/ID_MSG\([0-9]+\)/, "ID_MSG(" last_msg ")")
		last_msg++
	}
}
/ID_NUM\(/ {
	if (reset || match($0, /000/)) {
		sub(/ID_NUM\([0-9]+\)/, "ID_NUM(" last_msg ")")
		last_msg++
	}
}

/LOG_FMT[^(]/ {
	sub(/LOG_FMT/, "LOG_MSG(" last_msg ")")
	last_msg++
}
/LOG_[^A][^,]*, "/ {
	sub(/LOG_[^,]*,/, "& LOG_NUM(" last_msg ")")
	last_msg++
}
/ID_FMT[^(]/ {
	sub(/ID_FMT/, "ID_MSG(" last_msg ")")
	last_msg++
}

{
	print
}

END {
	print last_msg >"number_msg.txt";
	close "number_msg.txt"
}
