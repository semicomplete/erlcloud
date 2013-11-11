-record(r53_resource_record, {value::string()}).
-type(r53_resource_record()::#r53_resource_record{}).
-record(r53_record_set, 
        {name::string(),
         type="A"::string(),
         ttl=3600::number(),
         resource_records::[r53_resource_record()]}).
-type(r53_record_set()::#r53_record_set{}).
