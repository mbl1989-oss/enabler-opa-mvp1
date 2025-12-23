FROM openpolicyagent/opa:latest
COPY policy.rego /policy.rego
EXPOSE 8181
CMD ["run", "--server", "/policy.rego"]
