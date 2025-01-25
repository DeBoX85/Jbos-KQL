
# **KQL Query Reference Guide**

## **Introduction**

Kusto Query Language (KQL) is a powerful, read-only query language used in Azure services like Azure Monitor, Azure Log Analytics, Azure Sentinel, and Azure Data Explorer. It enables users to query and analyze large datasets quickly and efficiently, making it an essential tool for Azure operations.

### **Where to Use KQL**
- **Azure Monitor**: Analyze telemetry data and configure alerts.
- **Azure Log Analytics**: Query and analyze logs collected from Azure resources.
- **Azure Sentinel**: Investigate security events and identify potential threats.
- **Azure Data Explorer**: Perform advanced data analysis on large datasets.

For more information, check out the official [KQL Documentation](https://learn.microsoft.com/en-us/azure/data-explorer/kql/).

---

## **KQL Queries by Use Case**

### **1. Retrieve Security Events by Severity**
- **Description**: Fetches security events categorized by severity levels (`Error` and `Warning`) over the past 24 hours.
- **Purpose**: Monitor critical security events that may require immediate action.
- **Where to Use**: Azure Log Analytics or Azure Sentinel, with `SecurityEvent` logs.

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventLevelName in ("Error", "Warning")
| summarize Count = count() by bin(TimeGenerated, 1h), EventLevelName
| order by TimeGenerated desc
```

---

### **2. Monitor Failed Login Attempts**
- **Description**: Identifies failed login attempts (Event ID 4625) over the past 7 days.
- **Purpose**: Detect potential unauthorized access attempts and improve security posture.
- **Where to Use**: Azure Log Analytics or Azure Sentinel, focusing on `SecurityEvent` logs.

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedLogins = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

---

### **3. Identify Top Accounts with Failed Logins**
- **Description**: Lists the top 10 user accounts with the most failed login attempts in the past 30 days.
- **Purpose**: Pinpoint user accounts experiencing issues or potential brute-force attacks.
- **Where to Use**: Azure Log Analytics or Azure Sentinel, analyzing `SecurityEvent` logs.

```kql
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4625
| summarize FailedLogins = count() by TargetAccount
| top 10 by FailedLogins desc
```

---

### **4. Track Resource Heartbeats**
- **Description**: Monitors heartbeat signals from Azure resources to ensure they are active and responsive.
- **Purpose**: Verify the availability and health of resources.
- **Where to Use**: Azure Monitor or Azure Log Analytics, within a workspace collecting `Heartbeat` data.

```kql
Heartbeat
| summarize LastHeartbeat = max(TimeGenerated) by Resource
| where LastHeartbeat < ago(5m)
```

---

### **5. Analyze Azure Logic Apps Run Failures**
- **Description**: Retrieves failed runs of Azure Logic Apps over the past 7 days.
- **Purpose**: Diagnose and troubleshoot issues within Logic Apps workflows.
- **Where to Use**: Azure Log Analytics with diagnostics enabled for Logic Apps.

```kql
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where ResourceType == "MICROSOFT.LOGIC/WORKFLOWS"
| where Status_s == "Failed"
| summarize FailureCount = count() by Resource, bin(TimeGenerated, 1d)
| order by FailureCount desc
```

---

### **6. Evaluate Virtual Machine Performance**
- **Description**: Assesses CPU utilization for virtual machines over the past week.
- **Purpose**: Monitor VM performance and identify potential bottlenecks.
- **Where to Use**: Azure Monitor or Azure Log Analytics, collecting performance counters for VMs.

```kql
Perf
| where TimeGenerated > ago(7d)
| where ObjectName == "Processor" and CounterName == "% Processor Time"
| summarize AvgCPU = avg(CounterValue) by Computer, bin(TimeGenerated, 1h)
| order by AvgCPU desc
```

---

### **7. Detect Unused Public IP Addresses**
- **Description**: Identifies public IP addresses not in use for the past 30 days.
- **Purpose**: Optimize resource allocation and reduce unnecessary costs.
- **Where to Use**: Azure Log Analytics, analyzing `AzureActivity` logs.

```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where ResourceType == "Microsoft.Network/publicIPAddresses"
| summarize LastUsed = max(TimeGenerated) by ResourceId
| where LastUsed < ago(30d)
```

---

### **8. Summarize Data Ingestion by Table**
- **Description**: Provides a summary of data ingestion volumes by table over the past 24 hours.
- **Purpose**: Monitor data ingestion and manage Log Analytics workspace usage.
- **Where to Use**: Azure Monitor or Azure Log Analytics, analyzing `Usage` data.

```kql
Usage
| where TimeGenerated > ago(24h)
| summarize IngestedDataMB = sum(Quantity) / 1024 by DataType
| order by IngestedDataMB desc
```

---

## **Next Steps**
- Save these queries in your Azure Monitor or Log Analytics workspace as reusable query templates.
- Integrate these queries into Azure Workbooks for better visualization.
- Expand this list with custom queries tailored to your organization's needs.

Feel free to contribute additional queries or suggestions by submitting a pull request!

---

### **How to Use This Guide**
- **Copy-paste queries** directly into the Azure Monitor Logs or Log Analytics Query editor.
- Modify filters (e.g., time range, resource type) to fit your use case.
- Combine these queries with visualizations in Azure Workbooks for dashboards.
