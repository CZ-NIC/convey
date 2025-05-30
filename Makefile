MANIFEST := convey/__init__.py
TAG := $(shell grep "^__version" $(MANIFEST) | pz --search '"(\d+\.\d+\.\d+(?:-(?:rc|alpha|beta)\.?\d+)?)?"')

.PHONY: release validate pre-check
default: release

release:
	@echo "Tagging release $(TAG)"
	git tag $(TAG)
	git push origin $(TAG)
	@#echo "Deploying documentation..."
	@	#mkdocs gh-deploy
