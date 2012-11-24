#!/usr/bin/awk -f
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

function main(){
    #note: this is executed after the BEGIN block
    do{
        shc_cmnd_snag( "ps uxww", ps_out)
        for (i in ps_out){
            if ( str_matches(ps_out[i], "awk -f .*mate.awk") ) {
                split(ps_out[i],process,FS)
                pids[process[2]] = "True"
                running++
            }
        }
        if (running > 1) {
            for ( pid in pids )
                pidlist = pidlist OFS pid
            system("kill " pidlist)
            exit
        } else {
            running = 0
        }
        for (i in ps_out){
            if ( str_matches(ps_out[i], "xscreensaver -nosplash") ) {
                system("xscreensaver-command -deactivate")
            }

        }
        system("sleep " rest_interval)
    }while (1)

}

BEGIN{
    rest_interval = 90
    main()
}
