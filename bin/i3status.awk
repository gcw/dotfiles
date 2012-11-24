#!/usr/bin/awk -f
# Quick script to serve as a status notifier in i3wm. 


function str_matches(st_base, pt_base, ary_match_catch, st_old_rs, st_old_rl,
                        st_old_offset, st_offset, match_count ){
    #usage: str_matches(s, p[, a])
    #purpose: search string 's' for pattern 'p'. Return the total number of
    #         (non-nested) longest-matches of pattern 'p' in string 's'. 
    #         if optional array [a] is supplied it is populated as followes:
    #               a[n]            = value of match #n
    #               a[n,"START"]    = index of first char of match 1
    #               a[n,"LENGTH"]   = length of match #n
    #               here 'n' is a number less than or equal to the total number
    #               of matches.
    #example:
    #   str_matches( "cat dog fox", "[a-z]o[a-z]", matches )  -->   2  
    #       In the above example matches[1] would be set to "dog", 
    #       matches[1,"START"] will be set to 5 and matches[1,"LENGTH"] will
    #       be set to 3
    #   str_matches( "x a b c o", "[abc]" )                   -->   3
    #       In the above example there is not optional array to populate with
    #       with values, starting points, and lengths. 
    #   str_matches( "a b c d e f",/[abc]/)                   --> ERROR
    #       Invalid parameter (second argument should be "[abc]" instead of 
    #       /[abc]/
    #notes: your patterns should not be regex literals beginning and ending with 
    #       '/', instead they should be strings in double quotes. 

    if (RSTART)
        st_old_rs = RSTART
    if (RLENGTH)
        st_old_rl = RLENGTH
    st_base_len = length(st_base) 
    
    st_offset = 1
    #st_end = st_base_len
    while (match(substr(st_base, st_offset), pt_base)) {
        st_offset = RSTART + RLENGTH + st_old_offset
        ary_match_catch[++match_count] = substr(st_base, 
                                                st_old_offset + RSTART,
                                                RLENGTH)
        ary_match_catch[match_count,"START"] = RSTART + st_old_offset
        ary_match_catch[match_count,"LENGTH"] = RLENGTH
        st_old_offset = st_offset - 1
    }
    if (st_old_rs)
        RSTART = st_old_rs
    if (st_old_rl)
        RLENGTH = st_old_rl
    return match_count
}

function shc_cmnd_snag( cmnd_string, base_ary,  cmnd_out_counter ){
    #usage: shc_cmnd_snag(s, a)
    #purpose: capture the standard output of command 's' to array 'a' 
    #         return the number of lines of output
    #notes: I/O redirection is not handled directly buy this function. If you
    #       want to use file descriptors it's up to you include that in your
    #       command
    for ( cmnd_out_counter = 1 ;
            cmnd_string | getline base_ary[cmnd_out_counter] ;
            cmnd_out_counter += 1){
        #empty loop
    }
    close(cmnd_string)
    return cmnd_out_counter -  1
}

function sleep(time,   command){
    command = sprintf("sleep %i", time)
    return system(command)
}

function stanza_out( name, instance, color, full_text,    stanza_val){
    stanza["name"] = name
    stanza["instance"] = instance
    stanza["color"] = color
    stanza["full_text"] = full_text
    stanza_val = "{"
    for (element in stanza){
        if (stanza[element]) {
            current_count++
            stanza_val = stanza_val sprintf("\"%s\":\"%s\",",
                                        element, stanza[element])
        }
    }
    gsub(/[,]$/,"},",stanza_val) #replace the last comma with stanza close
    return stanza_val
}

function get_fs( fsRE,   i, a, name, instance, color, full_text, matches ){
    shc_cmnd_snag( "df -h", fs_out)
    for (i in fs_out){
        if ( str_matches(fs_out[i], fsRE, matches) > 0 ) {
            split(fs_out[i], a, FS)
            name = "size check"
            instance = matches[1]
            full_text = sprintf("%s: %s/%s(%s)", instance, a[4], a[2], a[5]) 
            if ( int(a[5])  < 50) 
                color = GREEN
            if ( int(a[5])  > 50) 
                color = YELLOW
            if ( int(a[5])  > 80) 
                color = ORANGE
            if ( int(a[5])  > 90) 
                color = RED
            return stanza_out(name, instance, color, full_text)
        }
    }

}

function get_ip( interface,    i, a){
    shc_cmnd_snag( "ifconfig " interface, fs_out)
    for (i in fs_out){
        if (fs_out[i] ~ /inet /) {
            name = "interface"
            instance = interface
            split(fs_out[i], a, FS)
            if ( ! a[2] ) {
                full_text = "DOWN"
                color = RED
            } else {
                full_text = interface ": " a[2]
                color = GREEN
            }
            return stanza_out(name, instance, color, full_text)
        }
    }

}

function check_xscreensaver(    i, ps_out){
    name = "XSS"
    instance = name
    color = RED
    full_text = name ": DOWN"
    shc_cmnd_snag( "ps uxww", ps_out)
    for (i in ps_out){
        if ( str_matches(ps_out[i], "xscreensaver -nosplash") ) {
            color = GREEN
            full_text = name ": RUNNING"
        }
    }
    return stanza_out(name, instance, color, full_text)
}

function check_mate(    i, ps_out){
    name = "mate"
    instance = name
    color = YELLOW
    full_text = name ": DOWN"
    shc_cmnd_snag( "ps uxww", ps_out)
    for (i in ps_out){
        if ( str_matches(ps_out[i], "awk -f .*mate.awk") ) {
            color = ORANGE
            full_text = name ": RUNNING"
        }
    }
    return stanza_out(name, instance, color, full_text)
}

function clock(format){
    name = "clock"
    instance = name
    color = CYAN
    if (format)
        shc_cmnd_snag("date +" format, clock_out)
    else
        shc_cmnd_snag("date", clock_out)

    full_text = clock_out[1]
    return stanza_out(name, instance, color, full_text)
}

BEGIN {
    interval = 5
    #GREEN = "#00FF00"
    GREEN = "#00AF00"
    YELLOW = "#FFFF00"
    ORANGE = "#FF8000"
    RED = "#FF0000"
    CYAN = "#07DBDB"
    printf("{\"version\":1}\n[\n")
    do {
        stanza_line = "["
        value =  get_fs("/$")
        sub(/$/,check_xscreensaver(),stanza_line)   #append return value
        sub(/$/,check_mate(),stanza_line)           #append return value
        sub(/$/,get_fs("/$"),stanza_line)           #append return value
        sub(/$/,get_ip("re0"),stanza_line)          #append return value
        sub(/$/,clock(),stanza_line)                #append return value   
        sub(/[,]$/,"],",stanza_line) #remove trailing comma before entry end
        print stanza_line
        runs++
    } while ( sleep(interval) == 0 )
}
