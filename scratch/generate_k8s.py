import os
import yaml

MANIFESTS_DIR = os.path.join(os.path.dirname(__file__), "..", "k8s")
os.makedirs(MANIFESTS_DIR, exist_ok=True)

def write_yaml(filename, *docs):
    path = os.path.join(MANIFESTS_DIR, filename)
    with open(path, "w") as f:
        yaml.dump_all(docs, f, default_flow_style=False)

def create_deployment(name, image, ports, env=None, args=None, volume_mounts=None):
    container = {
        "name": name,
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "ports": [{"containerPort": p} for p in ports]
    }
    if env:
        container["env"] = [{"name": k, "value": str(v)} for k, v in env.items()]
    if args:
        container["args"] = args
    if volume_mounts:
        container["volumeMounts"] = volume_mounts
        
    spec = {
        "replicas": 1,
        "selector": {"matchLabels": {"app": name}},
        "template": {
            "metadata": {"labels": {"app": name}},
            "spec": {"containers": [container]}
        }
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": spec
    }

def create_service(name, ports):
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name},
        "spec": {
            "selector": {"app": name},
            "ports": [{"name": f"port-{p}", "port": p, "targetPort": p} for p in ports]
        }
    }

# 1. Postgres
write_yaml("postgres.yaml", 
    create_deployment("postgres", "postgres:15-alpine", [5432], {"POSTGRES_USER": "soc_user", "POSTGRES_PASSWORD": "soc_password", "POSTGRES_DB": "soc_db"}),
    create_service("postgres", [5432])
)

# 2. Neo4j
write_yaml("neo4j.yaml", 
    create_deployment("neo4j", "neo4j:5.12", [7474, 7687], {"NEO4J_AUTH": "neo4j/soc_password"}),
    create_service("neo4j", [7474, 7687])
)

# 3. Qdrant
write_yaml("qdrant.yaml", 
    create_deployment("qdrant", "qdrant/qdrant", [6333, 6334]),
    create_service("qdrant", [6333, 6334])
)

# 4. Redis
write_yaml("redis.yaml", 
    create_deployment("redis", "redis:7-alpine", [6379]),
    create_service("redis", [6379])
)

# 5. Zookeeper & Kafka
zk_deploy = create_deployment("zookeeper", "confluentinc/cp-zookeeper:7.5.0", [2181], {"ZOOKEEPER_CLIENT_PORT": "2181"})
zk_svc = create_service("zookeeper", [2181])
kafka_deploy = create_deployment("kafka", "confluentinc/cp-kafka:7.5.0", [9092], {
    "KAFKA_ZOOKEEPER_CONNECT": "zookeeper:2181",
    "KAFKA_ADVERTISED_LISTENERS": "PLAINTEXT://kafka:9092",
    "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR": 1
})
kafka_svc = create_service("kafka", [9092])
write_yaml("kafka.yaml", zk_deploy, zk_svc, kafka_deploy, kafka_svc)

# 6. ClickHouse
write_yaml("clickhouse.yaml", 
    create_deployment("clickhouse", "clickhouse/clickhouse-server", [8123, 9000]),
    create_service("clickhouse", [8123, 9000])
)

# 7. Backend
backend_env = {
    "DATABASE_URL": "postgresql://soc_user:soc_password@postgres:5432/soc_db",
    "NEO4J_URI": "bolt://neo4j:7687",
    "NEO4J_USER": "neo4j",
    "NEO4J_PASSWORD": "soc_password",
    "QDRANT_URL": "http://qdrant:6333",
    "REDIS_URL": "redis://redis:6379",
    "KAFKA_BOOTSTRAP_SERVERS": "kafka:9092",
    "CLICKHOUSE_HOST": "clickhouse"
}
write_yaml("backend.yaml", 
    create_deployment("soc-backend", "edysor-backend:latest", [8000], backend_env),
    create_service("soc-backend", [8000])
)

# 8. Frontend
write_yaml("frontend.yaml", 
    create_deployment("frontend", "edysor-frontend:latest", [80]),
    create_service("frontend", [80])
)

print(f"Generated all K8s manifests in {MANIFESTS_DIR}")
