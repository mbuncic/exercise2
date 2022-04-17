# Exercise 2

1. Clone this repository.
2. In directory `portscan/` run `docker build --tag portscan:dev .` Change tag to match your repository.
3. Run `docker run --rm --volume=portscanvol:/app/data portscan:dev [ip_or_cidr]`.
4. Run step 3 again several times, changing scan target or opened ports on target and observe changes in output.
5. Push image to a public repository.
6. In scanner.yaml, change spec.containers.image value to match tag and spec.containers.args to desired scan target.
7. Run `kubectl apply -f scanner.yaml`.
8. Observe changes in pod logs.