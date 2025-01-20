#export TAG := `grep version pyproject.toml | pz --search '"(\d+\.\d+\.\d+(?:rc\d+)?)?"'`
export TAG := `grep version convey/__init__.py | pz --search '"(\d+\.\d+\.\d+(?:rc\d+)?)?"'`

release:
	git tag $(TAG)
	git push origin $(TAG)
	#mkdocs gh-deploy
