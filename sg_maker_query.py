sprint_hostname_list='''
SELECT
    upper(hostname) hostname,
    as_is_ip,
    to_be_ip,
    to_be_subnet_cidr,
    sprint,
    service_admin,
    server_admin,
    migration_admin
FROM
    "application_discovery_service_database"."machine_info"
'''


sprint_all_ads_info='''
SELECT source_ip, target_ip, 6 as protocol, port, source_hostname, destination_hostname
FROM
  (
    SELECT
    	(
    		CASE
    			WHEN (SMI.to_be_ip IS NULL OR SMI.to_be_ip = '') THEN AA.inbound_source_ip
    			ELSE SMI.to_be_ip
    		END
    	) source_ip,
    	(
    		CASE
    			WHEN (DMI.to_be_ip IS NULL OR DMI.to_be_ip = '') THEN AA.inbound_destination_ip
    			ELSE DMI.to_be_ip
    		END
    	) target_ip,
    	AA.inbound_destination_port port,
        upper(SMI.hostname) source_hostname,
        upper(DMI.hostname) destination_hostname
    FROM
    	(
    		SELECT
    			B.inbound_source_ip,
    			B.inbound_destination_ip,
    			B.inbound_destination_port
    		FROM
    			"application_discovery_service_database"."processes_agent" A,
    			(
    				SELECT
    					agent_id,
    					agent_assigned_process_id,
    					source_ip as inbound_source_ip,
    					destination_ip as inbound_destination_ip,
    					destination_port as inbound_destination_port
    				FROM
    					"application_discovery_service_database"."inbound_connection_agent"
    				WHERE
    					source_ip != destination_ip
    				GROUP BY agent_id, agent_assigned_process_id, source_ip, destination_ip, destination_port
    			)B
    		WHERE
    			A.agent_id = B.agent_id
    			AND A.agent_assigned_process_id = B.agent_assigned_process_id
    		GROUP BY B.inbound_source_ip, B.inbound_destination_ip, B.inbound_destination_port
    	)AA
        JOIN (SELECT * FROM "application_discovery_service_database"."machine_info" WHERE sprint = '#{sprint}') DMI ON AA.inbound_destination_ip = DMI.as_is_ip
        LEFT JOIN "application_discovery_service_database"."machine_info" SMI ON AA.inbound_source_ip = SMI.as_is_ip
    UNION ALL

    SELECT
    	(
    		CASE
    			WHEN (SMI.to_be_ip IS NULL OR SMI.to_be_ip = '') THEN AA.outbound_source_ip
    			ELSE SMI.to_be_ip
    		END
    	) source_ip,
    	(
    		CASE
    			WHEN (DMI.to_be_ip IS NULL OR DMI.to_be_ip = '') THEN AA.outbound_destination_ip
    			ELSE DMI.to_be_ip
    		END
    	) target_ip,
    	AA.outbound_destination_port port,
        upper(SMI.hostname) source_hostname,
        upper(DMI.hostname) destination_hostname
    FROM
    	(
    		SELECT
    			C.outbound_source_ip,
    			C.outbound_destination_ip,
    			C.outbound_destination_port
    		FROM
    			"application_discovery_service_database"."processes_agent" A,
    			(
    				SELECT
    					agent_id,
    					agent_assigned_process_id,
    					source_ip as outbound_source_ip,
    					destination_ip as outbound_destination_ip,
    					destination_port as outbound_destination_port
    				FROM
    					"application_discovery_service_database"."outbound_connection_agent"
    				WHERE
    					source_ip != destination_ip
    				GROUP BY agent_id, agent_assigned_process_id, source_ip, destination_ip, destination_port
    			)C
    		WHERE
    			A.agent_id = C.agent_id
    			AND A.agent_assigned_process_id = C.agent_assigned_process_id
    		GROUP BY C.outbound_source_ip, C.outbound_destination_ip, C.outbound_destination_port
    	) AA
    	JOIN (SELECT * FROM "application_discovery_service_database"."machine_info" WHERE sprint = '#{sprint}') SMI ON AA.outbound_source_ip = SMI.as_is_ip
    	LEFT JOIN "application_discovery_service_database"."machine_info" DMI ON AA.outbound_destination_ip = DMI.as_is_ip
  )
GROUP BY source_ip, target_ip, port, source_hostname, destination_hostname
ORDER BY port, target_ip, source_ip
'''

vpc_flow_query = '''
select
  pkt_srcaddr,pkt_dstaddr,protocol,destination_port
from
  vpc_flow_log
where
  tcp_flags in (2,6,7)
  and (pkt_dstaddr like '10.248%' or pkt_dstaddr like '10.249%')
  and action like 'A%'
group by pkt_srcaddr, pkt_dstaddr, destination_port, protocol
'''


risc_application_infos='''
type RISC
Application 스택 별
RISC login(portal.reiscnetworks.com)
-> Assessment 선택
-> Add Inteligence -> Available Reports ->
-> Detailed Application Dependency Data -> View Now
-> Business Service -All Flows Export -> Select Application Stack -> Refresh data
-> Export All


type RISCALL
RISC login(portal.reiscnetworks.com)
-> Assessment 선택
-> Add Inteligence -> Available Reports ->
-> Detailed Application Dependency Data -> Download
압축 해제 후 detailed_application_dependency_data.csv -> source.csv 로 변경
'''
