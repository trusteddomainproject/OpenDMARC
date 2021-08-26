This is a port of the OpenDMARC database and utilities to SQLite. 
It's  been pretty straightforward work.  The biggest differences I've
found are:

- SQLite only allows one key per table.  Multiple keys are simulated
with indexes. 
- There's no TINYINT in SQLite.  All these have been
promoted to INTEGERs. 
- There's no UNSIGNED INTEGER in SQLite.  This
has been simulated with CHECK constraints. 
- SQLite doesn't have the
plethora of DATE/TIME formats that MySQL has so all dates/times are
stored in the database as Unix epoch times.  This pushes the issue of
date/time formatting onto the *perl(1)* utilities.

I've made **_no changes at all_** to the daemon.  The command-line
switches to the *perl(1)* utilities have only changed because of the
nature of SQLite...there's no *dbhost, dbuser, deport,* etc.

In the *perl(1)* utilities, I use `constant`s to highlight the
differences with the following `BEGIN` block:
```
BEGIN {

    my $me = basename($0);      # local to block
    
    use constant MYSQL  => 0;
    use constant SQLITE => 1;    
    
    if ( ! (MYSQL || SQLITE) )
    {
        print STDERR "$me: You must set one of MYSQL or SQLITE.\n";
        exit(1);
    }
    
    if ( MYSQL && SQLITE )
    {
        print STDERR "$me: You must set ONLY one of MYSQL or SQLITE.\n";
        exit(1);
    }

}
```
Database-dependent code sections look like this:
```
### begin DB dependent
#
if ( MYSQL )
{
     ...MySQL stuff...    
}

if ( SQLITE )
{
     ...SQLite stuff...    
}
#
### end DB dependent
```
so as to not lose anyone else's hard work...and to make the same code
work with both.

This code is offered **_as is_**.  I disclaim any ownership of my changes.  
I don't offer any support so please don't contact me.  *Caveat:*  This hasn't been
rigorously tested and I don't have a way to test MySQL.
way to test MySQL...

-- cc
