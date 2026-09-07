# Architecture

## Resource Group

rg-soc-lab

## Log Analytics Workspace

law-soc-lab

## Region

East US

## SIEM

Microsoft Sentinel

## Endpoint

LAB-WIN01
(To be deployed)

## Data Pipeline

Windows Endpoint
    ↓
Azure Monitor Agent
    ↓
Windows Security Events
    ↓
Log Analytics
    ↓
Microsoft Sentinel
    ↓
KQL Detection
    ↓
Alert / Incident
    ↓
Investigation
