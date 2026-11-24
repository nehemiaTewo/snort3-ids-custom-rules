-- v2 tuning: limit alert volume for the scan and brute-force rules.
-- A scan produced ~1,980 alerts per run under v1; one alert per attacking
-- source per 60 s carries the same information without flooding the analyst.
event_filter =
{
    { gid = 1, sid = 1000003, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 1000009, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 1000007, type = 'limit', track = 'by_dst', count = 1, seconds = 60 },
}
