### pip
pip install boto3 botocore retrying openpyxl requests pyyaml pandas

### 실행
start /high python sg_firewall_maker.py --type RISCALL --source {Source File Path} --machines {Machine List File Path} --sprint {machine sprint}

### 인자 정보
- type
    - ADS
        - AWS Application Discovery Service 를 사용해서 분석할 경우
    - RISC
        - RISC Application Stack 별 연계성 정보로 분석할 경우
    - RISCALL
        - RISC 전체 연계성 정보로 분석할 경우
    - VPCFLOW
        - VPC Flow Logs 로 분석할 경우
- source
    - 연계 정보 csv파일 위치
- machines
    - 마이그레이션 대상 머신 정보 csv파일 위치
- sprint
    - 마이그레이션 스프린트 번호



### sg_firewall_maker.yaml
```
        verified_ip_range :
            AS-IS Infra IP Ranges
        aws_vpc_ranges :
            이관될 AWS IP Range
        exclude_ports :
            TCP:
                - 제외할 포트
            UDP:
                - 제외할 포트
        exclude_ip_ranges :
            공통으로 접속되는 AD / 접근 제어 서버 IP등
            SG 설정에서 제외 됨.
        firewall_application_form:
            - Allow/Deny : Allow
            - Expiration_Date : "#add_year# 1"
            - Requester : "" #"#service_admin#"
            - Remarks : "#hostname# by Automation"
        security_group:
            ip_ranges_treated_equally:
                AWS SG 를 그릴 때 묶음 단위 IP Ranges
            ref_value_of_treat_as_range : 5
                ex> 5일 경우
                1)
                10.1.1.1
                10.1.1.2
                10.1.1.3
                10.1.1.4
                10.1.1.5
                    가 80 포트로 접근할 경우
                10.0.0.0/8 80 오픈
                2)
                10.1.1.1 이  5개의 port 로 연결 시도 할 경우
                10.1.1.1 Any 오픈
            common_security_rules: #VPC 혹은 Subnet 단위 공통 SG 사용시 등록 SG 출력시 제외
                10.10.10.0/24: #Range Example 1
                    All: # All Traffic
                        - 20.0.0.0/9
                        - 30.128.0.0/10
                    TCP:
                        - 0.0.0.0/0:
                            start: 80
                            end: 80
                        - 10.10.150.122/32:
                            start: 0
                            end: 65535
                    UDP:
                        - 10.10.0.0/16:
                            start: 0
                            end: 65535
                10.10.20.0/24: #Range Example 2
                    All:
                        - 10.0.0.0/8
                    TCP:
                        - 10.10.20.4/32:
                            start: 0
                            end: 65535
                    UDP:
                        - 10.10.20.0/24:
                            start: 0
                            end: 65535
```


### machine_info.csv
Machines Information to be Migrated

- Columns
    - hostname
        - Machine's hostname
    - as_is_ip
        - Machine's as-is IP
    - to_be_ip
        - Machine's to-be IP
    - to_be_subnet_cidr
        - Subnet CIDR where the machine will be located
    - sprint
        - Sprint number from which the machine has been migrated or will be migrated



### source.csv
sg_maker_query.py
내용을 참조하여 RISC/VPC Flow logs/ADS 디스커버리 로우 데이터 출력.

VPC/RISC 방식의 경우 Sprint 별로 돌려야 함.(sprint required)
